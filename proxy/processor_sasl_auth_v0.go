package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/grepplabs/kafka-proxy/proxy/protocol"
	"github.com/sirupsen/logrus"

	"strings"
)

type SaslAuthV0RequestHandler struct {
}

type SaslAuthV0ResponseHandler struct {
}

func (handler *SaslAuthV0RequestHandler) handleRequest(dst DeadlineWriter, src DeadlineReaderWriter, ctx *RequestsLoopContext) (readErr bool, err error) {
	if readErr, err = copySaslAuthRequest(dst, src, ctx); err != nil {
		return readErr, err
	}
	if err = ctx.putNextHandlers(defaultRequestHandler, defaultResponseHandler); err != nil {
		return false, err
	}
	return false, nil
}

func (handler *SaslAuthV0ResponseHandler) handleResponse(dst DeadlineWriter, src DeadlineReader, ctx *ResponsesLoopContext) (readErr bool, err error) {
	if readErr, err = copySaslAuthResponse(dst, src, ctx.timeout); err != nil {
		return readErr, err
	}
	return false, nil // nextResponse
}

func copySaslAuthRequest(dst DeadlineWriter, src DeadlineReader, ctx *RequestsLoopContext) (readErr bool, err error) {
	// timeout time.Duration
	// , buf []byte
	requestDeadline := time.Now().Add(ctx.timeout)
	err = dst.SetWriteDeadline(requestDeadline)
	if err != nil {
		return false, err
	}
	err = src.SetReadDeadline(requestDeadline)
	if err != nil {
		return true, err
	}

	sizeBuf := make([]byte, 4) // Size => int32
	if _, err = io.ReadFull(src, sizeBuf); err != nil {
		return true, err
	}

	length := binary.BigEndian.Uint32(sizeBuf)
	if int32(length) > protocol.MaxRequestSize {
		return true, protocol.PacketDecodingError{Info: fmt.Sprintf("auth message of length %d too large", length)}
	}
	logrus.Debugf("SASL auth request length %v", length)

	resp := make([]byte, int(length))
	if _, err = io.ReadFull(src, resp); err != nil {
		return true, err
	}
	// payload := bytes.Join([][]byte{sizeBuf[4:], resp}, nil)

	// saslReqV0orV1 := &protocol.SaslHandshakeRequestV0orV1{Version: 0}
	// req := &protocol.Request{Body: saslReqV0orV1}
	// if err = protocol.Decode(payload, req); err != nil {
	// 	return true, err
	// }

	tokens := strings.Split(string(resp), "\x00")

	logrus.Debugf("SASL usernme: %s", tokens[1])

	ctx.auditLog.username = tokens[1]

	// write - send to broker
	if _, err = dst.Write(sizeBuf); err != nil {
		return false, err
	}
	if readErr, err = myCopyN(dst, src, int64(length), ctx.buf); err != nil {
		return readErr, err
	}
	return false, nil
}

func copySaslAuthResponse(dst DeadlineWriter, src DeadlineReader, timeout time.Duration) (readErr bool, err error) {
	//logrus.Printf("SASL auth response")

	responseDeadline := time.Now().Add(timeout)
	err = dst.SetWriteDeadline(responseDeadline)
	if err != nil {
		return false, err
	}
	err = src.SetReadDeadline(responseDeadline)
	if err != nil {
		return true, err
	}

	header := make([]byte, 4)
	_, err = io.ReadFull(src, header)
	if err != nil {
		return true, err
	}

	if _, err = dst.Write(header); err != nil {
		return false, err
	}
	return false, nil
}
