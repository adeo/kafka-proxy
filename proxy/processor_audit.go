package proxy

import (
	"io"
	// "strings"
	"fmt"
	"strconv"
	"time"

	"github.com/grepplabs/kafka-proxy/proxy/protocol"

	"github.com/sirupsen/logrus"
)

type AuditRequestHandler struct {
}

type AuditResponseHandler struct {
}

func (handler *AuditRequestHandler) handleRequest(dst DeadlineWriter, src DeadlineReaderWriter, ctx *RequestsLoopContext) (readErr bool, err error) {
	// logrus.Println("Await Kafka request")

	// waiting for first bytes or EOF - reset deadlines
	src.SetReadDeadline(time.Time{})
	dst.SetWriteDeadline(time.Time{})

	keyVersionBuf := make([]byte, 8) // Size => int32 + ApiKey => int16 + ApiVersion => int16

	if _, err = io.ReadFull(src, keyVersionBuf); err != nil {
		return true, err
	}

	requestKeyVersion := &protocol.RequestKeyVersion{}
	if err = protocol.Decode(keyVersionBuf, requestKeyVersion); err != nil {
		return true, err
	}
	logrus.Debugf("Kafka request key %v, version %v, length %v", requestKeyVersion.ApiKey, requestKeyVersion.ApiVersion, requestKeyVersion.Length)

	if requestKeyVersion.ApiKey < minRequestApiKey || requestKeyVersion.ApiKey > maxRequestApiKey {
		return true, fmt.Errorf("api key %d is invalid", requestKeyVersion.ApiKey)
	}

	proxyRequestsTotal.WithLabelValues(ctx.brokerAddress, strconv.Itoa(int(requestKeyVersion.ApiKey)), strconv.Itoa(int(requestKeyVersion.ApiVersion))).Inc()
	proxyRequestsBytes.WithLabelValues(ctx.brokerAddress).Add(float64(requestKeyVersion.Length + 4))

	if _, ok := ctx.forbiddenApiKeys[requestKeyVersion.ApiKey]; ok {
		return true, fmt.Errorf("api key %d is forbidden", requestKeyVersion.ApiKey)
	}

	logrus.Error(requestKeyVersion.ApiKey == 36)

	if requestKeyVersion.ApiKey == 36 {
		logrus.Errorf("Oi")
	}

	// send inFlightRequest to channel before myCopyN to prevent race condition in proxyResponses
	if err = sendRequestKeyVersion(ctx.openRequestsChannel, openRequestSendTimeout, requestKeyVersion); err != nil {
		return true, err
	}

	requestDeadline := time.Now().Add(ctx.timeout)
	err = dst.SetWriteDeadline(requestDeadline)
	if err != nil {
		return false, err
	}
	err = src.SetReadDeadline(requestDeadline)
	if err != nil {
		return true, err
	}

	// write - send to broker
	if _, err = dst.Write(keyVersionBuf); err != nil {
		return false, err
	}
	// 4 bytes were written as keyVersionBuf (ApiKey, ApiVersion)
	if readErr, err = myCopyN(dst, src, int64(requestKeyVersion.Length-4), ctx.buf); err != nil {
		return readErr, err
	}
	if requestKeyVersion.ApiKey == apiKeySaslHandshake {
		if requestKeyVersion.ApiVersion == 0 {
			return false, ctx.putNextHandlers(saslAuthV0RequestHandler, saslAuthV0ResponseHandler)
		} else {

		}
	}

	// auditRequest(ctx)

	return false, ctx.putNextHandlers(defaultRequestHandler, defaultResponseHandler)
}

func (handler *AuditResponseHandler) handleResponse(dst DeadlineWriter, src DeadlineReader, ctx *ResponsesLoopContext) (readErr bool, err error) {
	logrus.Printf("AUDIT RESPONSE")
	return false, nil //next handler
}

