/*
   conflux - Distributed database synchronization library
	Based on the algorithm described in
		"Set Reconciliation with Nearly Optimal	Communication Complexity",
			Yaron Minsky, Ari Trachtenberg, and Richard Zippel, 2004.

   Copyright (c) 2012-2015  Casey Marshall <cmars@cmarstech.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package recon

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pkg/errors"

	cf "hockeypuck/conflux"
)

var (
	SksZpNbytes int

	maxReadLen = 1 << 24
)

func init() {
	SksZpNbytes = cf.P_SKS.BitLen() / 8
	if cf.P_SKS.BitLen()%8 != 0 {
		SksZpNbytes++
	}
}

func PadSksElement(zb []byte) []byte {
	for len(zb) < SksZpNbytes {
		zb = append(zb, byte(0))
	}
	return zb
}

type MsgType uint8

const (
	MsgTypeReconRqstPoly = MsgType(0)
	MsgTypeReconRqstFull = MsgType(1)
	MsgTypeElements      = MsgType(2)
	MsgTypeFullElements  = MsgType(3)
	MsgTypeSyncFail      = MsgType(4)
	MsgTypeDone          = MsgType(5)
	MsgTypeFlush         = MsgType(6)
	MsgTypeError         = MsgType(7)
	MsgTypeDbRqst        = MsgType(8)
	MsgTypeDbRepl        = MsgType(9)
	MsgTypeConfig        = MsgType(10)
)

func (mt MsgType) String() string {
	switch mt {
	case MsgTypeReconRqstPoly:
		return "ReconRqstPoly"
	case MsgTypeReconRqstFull:
		return "ReconRqstFull"
	case MsgTypeElements:
		return "Elements"
	case MsgTypeFullElements:
		return "FullElements"
	case MsgTypeSyncFail:
		return "SyncFail"
	case MsgTypeDone:
		return "Done"
	case MsgTypeFlush:
		return "Flush"
	case MsgTypeError:
		return "Error"
	case MsgTypeDbRqst:
		return "DbRqst"
	case MsgTypeDbRepl:
		return "DbRepl"
	case MsgTypeConfig:
		return "Config"
	}
	return "Unknown"
}

type ReconMsg interface {
	MsgType() MsgType
	unmarshal(r io.Reader) error
	marshal(w io.Writer) error
}

type emptyMsg struct{}

func (msg *emptyMsg) unmarshal(r io.Reader) error { return nil }

func (msg *emptyMsg) marshal(w io.Writer) error { return nil }

type textMsg struct{ Text string }

func (msg *textMsg) unmarshal(r io.Reader) (err error) {
	msg.Text, err = ReadString(r)
	return
}

func (msg *textMsg) marshal(w io.Writer) error {
	return WriteString(w, msg.Text)
}

type notImplMsg struct{}

func (msg *notImplMsg) unmarshal(r io.Reader) error {
	panic("not implemented")
}

func (msg *notImplMsg) marshal(w io.Writer) error {
	panic("not implemented")
}

func ReadInt(r io.Reader) (int, error) {
	buf := make([]byte, 4)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	n := int(binary.BigEndian.Uint32(buf))
	return n, err
}

func ReadLen(r io.Reader) (int, error) {
	n, err := ReadInt(r)
	if err != nil {
		return n, errors.WithStack(err)
	}
	if n > maxReadLen {
		return 0, errors.Errorf("read length %d exceeds maximum limit", n)
	}
	return n, nil
}

func WriteInt(w io.Writer, n int) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(n))
	_, err := w.Write(buf)
	return errors.WithStack(err)
}

func ReadString(r io.Reader) (string, error) {
	var n int
	n, err := ReadLen(r)
	if err != nil || n == 0 {
		return "", err
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(r, buf)
	return string(buf), err
}

func WriteString(w io.Writer, text string) error {
	err := WriteInt(w, len(text))
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = w.Write([]byte(text))
	return errors.WithStack(err)
}

func ReadBitstring(r io.Reader) (*cf.Bitstring, error) {
	nbits, err := ReadLen(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	bs := cf.NewBitstring(nbits)
	nbytes, err := ReadLen(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if nbits == 0 {
		return bs, nil
	}
	buf := make([]byte, nbytes)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	bs.SetBytes(buf)
	return bs, nil
}

func WriteBitstring(w io.Writer, bs *cf.Bitstring) error {
	err := WriteInt(w, bs.BitLen())
	if err != nil {
		return errors.WithStack(err)
	}
	err = WriteInt(w, len(bs.Bytes()))
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = w.Write(bs.Bytes())
	return errors.WithStack(err)
}

func ReadZZarray(r io.Reader) ([]cf.Zp, error) {
	n, err := ReadLen(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	arr := make([]cf.Zp, n)
	for i := 0; i < n; i++ {
		err := ReadZp(r, &arr[i])
		if err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return arr, nil
}

func WriteZZarray(w io.Writer, arr []cf.Zp) error {
	err := WriteInt(w, len(arr))
	if err != nil {
		return errors.WithStack(err)
	}
	for i := range arr {
		err = WriteZp(w, &arr[i])
		if err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

func ReadZSet(r io.Reader) (*cf.ZSet, error) {
	arr, err := ReadZZarray(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	zset := cf.NewZSet()
	zset.AddSlice(arr)
	return zset, nil
}

func WriteZSet(w io.Writer, zset *cf.ZSet) error {
	return WriteZZarray(w, zset.Items())
}

func ReadZp(r io.Reader, zp *cf.Zp) error {
	buf := make([]byte, SksZpNbytes)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return errors.WithStack(err)
	}
	zp.In(cf.P_SKS).SetBytes(buf)
	zp.Norm()
	return nil
}

func WriteZp(w io.Writer, z *cf.Zp) error {
	var err error
	num := z.Bytes()
	_, err = w.Write(num)
	if err != nil {
		return errors.WithStack(err)
	}
	if len(num) < SksZpNbytes {
		pad := make([]byte, SksZpNbytes-len(num))
		_, err = w.Write(pad)
	}
	return errors.WithStack(err)
}

type ReconRqstPoly struct {
	Prefix  *cf.Bitstring
	Size    int
	Samples []cf.Zp
}

func (msg *ReconRqstPoly) MsgType() MsgType {
	return MsgTypeReconRqstPoly
}

func (msg *ReconRqstPoly) String() string {
	return fmt.Sprintf("%v: prefix=%v size=%v elements=%v",
		msg.MsgType(), msg.Prefix, msg.Size, msg.Samples)
}

func (msg *ReconRqstPoly) marshal(w io.Writer) error {
	err := WriteBitstring(w, msg.Prefix)
	if err != nil {
		return errors.WithStack(err)
	}
	err = WriteInt(w, msg.Size)
	if err != nil {
		return errors.WithStack(err)
	}
	err = WriteZZarray(w, msg.Samples)
	return errors.WithStack(err)
}

func (msg *ReconRqstPoly) unmarshal(r io.Reader) error {
	var err error
	msg.Prefix, err = ReadBitstring(r)
	if err != nil {
		return errors.WithStack(err)
	}
	msg.Size, err = ReadLen(r)
	if err != nil {
		return errors.WithStack(err)
	}
	msg.Samples, err = ReadZZarray(r)
	return errors.WithStack(err)
}

type ReconRqstFull struct {
	Prefix   *cf.Bitstring
	Elements *cf.ZSet
}

func (msg *ReconRqstFull) String() string {
	return fmt.Sprintf("%v: prefix=%v (%d elements)",
		msg.MsgType(), msg.Prefix, msg.Elements.Len())
}

func (msg *ReconRqstFull) MsgType() MsgType {
	return MsgTypeReconRqstFull
}

func (msg *ReconRqstFull) marshal(w io.Writer) error {
	err := WriteBitstring(w, msg.Prefix)
	if err != nil {
		return errors.WithStack(err)
	}
	err = WriteZSet(w, msg.Elements)
	return errors.WithStack(err)
}

func (msg *ReconRqstFull) unmarshal(r io.Reader) error {
	var err error
	msg.Prefix, err = ReadBitstring(r)
	if err != nil {
		return errors.WithStack(err)
	}
	msg.Elements, err = ReadZSet(r)
	return errors.WithStack(err)
}

type Elements struct {
	*cf.ZSet
}

func (msg *Elements) String() string {
	return fmt.Sprintf("%v", msg.MsgType())
}

func (msg *Elements) MsgType() MsgType {
	return MsgTypeElements
}

func (msg *Elements) marshal(w io.Writer) error {
	err := WriteZSet(w, msg.ZSet)
	return errors.WithStack(err)
}

func (msg *Elements) unmarshal(r io.Reader) error {
	var err error
	msg.ZSet, err = ReadZSet(r)
	return errors.WithStack(err)
}

type FullElements struct {
	*cf.ZSet
}

func (msg *FullElements) String() string {
	return fmt.Sprintf("%v", msg.MsgType())
}

func (msg *FullElements) MsgType() MsgType {
	return MsgTypeFullElements
}

func (msg *FullElements) marshal(w io.Writer) error {
	err := WriteZSet(w, msg.ZSet)
	return errors.WithStack(err)
}

func (msg *FullElements) unmarshal(r io.Reader) error {
	var err error
	msg.ZSet, err = ReadZSet(r)
	return errors.WithStack(err)
}

type SyncFail struct {
	*emptyMsg
}

func (msg *SyncFail) String() string {
	return fmt.Sprintf("%v", msg.MsgType())
}

func (msg *SyncFail) MsgType() MsgType {
	return MsgTypeSyncFail
}

type Done struct {
	*emptyMsg
}

func (msg *Done) String() string {
	return fmt.Sprintf("%v", msg.MsgType())
}

func (msg *Done) MsgType() MsgType {
	return MsgTypeDone
}

type Flush struct {
	*emptyMsg
}

func (msg *Flush) String() string {
	return fmt.Sprintf("%v", msg.MsgType())
}

func (msg *Flush) MsgType() MsgType {
	return MsgTypeFlush
}

type Error struct {
	*textMsg
}

func (msg *Error) String() string {
	return fmt.Sprintf("%v: %v", msg.MsgType(), msg.Text)
}

func (msg *Error) MsgType() MsgType {
	return MsgTypeError
}

type DbRqst struct {
	*textMsg
}

func (msg *DbRqst) String() string {
	return fmt.Sprintf("%v: %v", msg.MsgType(), msg.Text)
}

func (msg *DbRqst) MsgType() MsgType {
	return MsgTypeDbRqst
}

type DbRepl struct {
	*textMsg
}

func (msg *DbRepl) String() string {
	return fmt.Sprintf("%v: %v", msg.MsgType(), msg.Text)
}

func (msg *DbRepl) MsgType() MsgType {
	return MsgTypeDbRepl
}

var RemoteConfigPassed string = "passed"
var RemoteConfigFailed string = "failed"

type Config struct {
	Version    string
	HTTPPort   int
	BitQuantum int
	MBar       int
	Filters    string
	Custom     map[string]string
}

func (msg *Config) String() string {
	return fmt.Sprintf("%v: Version=%v HTTPPort=%v BitQuantum=%v MBar=%v Filters=%s", msg.MsgType(),
		msg.Version, msg.HTTPPort, msg.BitQuantum, msg.MBar, msg.Filters)
}

func (msg *Config) MsgType() MsgType {
	return MsgTypeConfig
}

func (msg *Config) marshal(w io.Writer) error {
	if err := WriteInt(w, 5+len(msg.Custom)); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteString(w, "version"); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteString(w, msg.Version); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteString(w, "http port"); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteInt(w, 4); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteInt(w, msg.HTTPPort); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteString(w, "bitquantum"); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteInt(w, 4); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteInt(w, msg.BitQuantum); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteString(w, "mbar"); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteInt(w, 4); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteInt(w, msg.MBar); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteString(w, "filters"); err != nil {
		return errors.WithStack(err)
	}
	if err := WriteString(w, msg.Filters); err != nil {
		return errors.WithStack(err)
	}
	if msg.Custom != nil {
		for k, v := range msg.Custom {
			if err := WriteString(w, k); err != nil {
				return errors.WithStack(err)
			}
			if err := WriteString(w, v); err != nil {
				return errors.WithStack(err)
			}
		}
	}
	return nil
}

func (msg *Config) unmarshal(r io.Reader) error {
	n, err := ReadLen(r)
	if err != nil {
		return errors.WithStack(err)
	}
	msg.Custom = make(map[string]string)
	var ival int
	var k, v string
	for i := 0; i < n; i++ {
		k, err = ReadString(r)
		if err != nil {
			return errors.WithStack(err)
		}
		switch k {
		case "http port":
			fallthrough
		case "bitquantum":
			fallthrough
		case "mbar":
			// Read the int length
			if ival, err = ReadLen(r); err != nil {
				return errors.WithStack(err)
			} else if ival != 4 {
				return errors.Errorf("Invalid length=%d for integer config value %s", ival, k)
			}
			// Read the int
			if ival, err = ReadInt(r); err != nil {
				return errors.WithStack(err)
			}
		default:
			v, err = ReadString(r)
			if err != nil {
				return errors.WithStack(err)
			}
		}
		switch k {
		case "version":
			msg.Version = v
		case "http port":
			msg.HTTPPort = ival
		case "bitquantum":
			msg.BitQuantum = ival
		case "mbar":
			msg.MBar = ival
		case "filters":
			msg.Filters = v
		default:
			msg.Custom[k] = v
		}
	}
	return nil
}

func ReadMsg(r io.Reader) (ReconMsg, error) {
	msgSize, err := ReadLen(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	msgBuf := make([]byte, msgSize)
	_, err = io.ReadFull(r, msgBuf)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	br := bytes.NewBuffer(msgBuf)
	buf := make([]byte, 1)
	_, err = io.ReadFull(br, buf[:1])
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var msg ReconMsg
	msgType := MsgType(buf[0])
	switch msgType {
	case MsgTypeReconRqstPoly:
		msg = &ReconRqstPoly{}
	case MsgTypeReconRqstFull:
		msg = &ReconRqstFull{}
	case MsgTypeElements:
		msg = &Elements{}
	case MsgTypeFullElements:
		msg = &FullElements{}
	case MsgTypeSyncFail:
		msg = &SyncFail{}
	case MsgTypeDone:
		msg = &Done{}
	case MsgTypeFlush:
		msg = &Flush{}
	case MsgTypeError:
		msg = &Error{&textMsg{}}
	case MsgTypeDbRqst:
		msg = &DbRqst{&textMsg{}}
	case MsgTypeDbRepl:
		msg = &DbRepl{&textMsg{}}
	case MsgTypeConfig:
		msg = &Config{}
	default:
		return nil, errors.Errorf("unexpected message code: %d", msgType)
	}
	err = msg.unmarshal(br)
	return msg, errors.WithStack(err)
}

func WriteMsgDirect(w io.Writer, msg ReconMsg) error {
	data := bytes.NewBuffer(nil)
	buf := make([]byte, 1)
	buf[0] = byte(msg.MsgType())
	_, err := data.Write(buf)
	if err != nil {
		return errors.WithStack(err)
	}
	err = msg.marshal(data)
	if err != nil {
		return errors.WithStack(err)
	}
	err = WriteInt(w, data.Len())
	if err != nil {
		return errors.WithStack(err)
	}
	_, err = w.Write(data.Bytes())
	return errors.WithStack(err)
}

func WriteMsg(w io.Writer, msgs ...ReconMsg) error {
	bufw := bufio.NewWriter(w)
	for _, msg := range msgs {
		err := WriteMsgDirect(bufw, msg)
		if err != nil {
			return errors.WithStack(err)
		}
	}
	err := bufw.Flush()
	return errors.WithStack(err)
}
