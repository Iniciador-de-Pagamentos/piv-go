// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestParseDeviceInfo(t *testing.T) {
	t.Parallel()

	encoded := encodeManagementTLVs(
		[]byte{0x01, 0x02, 0x07, 0x3f},
		[]byte{0x02, 0x04, 0x01, 0x23, 0x45, 0x67},
		[]byte{0x03, 0x02, 0x02, 0x13},
		[]byte{0x04, 0x01, 0x83},
		[]byte{0x05, 0x03, 0x05, 0x07, 0x02},
	)

	got, err := parseDeviceInfo(encoded)
	if err != nil {
		t.Fatalf("parseDeviceInfo() error = %v", err)
	}
	if got.Serial() != 0x01234567 {
		t.Errorf("Serial() = 0x%08x, want 0x01234567", got.Serial())
	}
	if got.Version() != (Version{Major: 5, Minor: 7, Patch: 2}) {
		t.Errorf("Version() = %#v, want 5.7.2", got.Version())
	}
	if got.FormFactor() != FormfactorUSBCKeychainFIPS {
		t.Errorf("FormFactor() = 0x%02x, want 0x83", got.FormFactor())
	}
	if !got.IsFIPS() {
		t.Error("IsFIPS() = false, want true")
	}
	if got.SupportedUSBCapabilities() != Capability(0x073f) {
		t.Errorf("SupportedUSBCapabilities() = 0x%04x, want 0x073f", got.SupportedUSBCapabilities())
	}
	if got.EnabledUSBCapabilities() != Capability(0x0213) {
		t.Errorf("EnabledUSBCapabilities() = 0x%04x, want 0x0213", got.EnabledUSBCapabilities())
	}
}

func TestParseDeviceInfoCapabilityConstants(t *testing.T) {
	t.Parallel()

	got := CapabilityOTP |
		CapabilityU2F |
		CapabilityCCID |
		CapabilityOpenPGP |
		CapabilityPIV |
		CapabilityOATH |
		CapabilityHSMAuth |
		CapabilityFIDO2
	if got != 0x033f {
		t.Errorf("application capability mask = 0x%04x, want 0x033f", got)
	}
}

func TestParseDeviceInfoIgnoresUnknownTags(t *testing.T) {
	t.Parallel()

	encoded := encodeManagementTLVs(
		[]byte{0x7f, 0x03, 0xde, 0xad, 0xbe},
		[]byte{0x04, 0x01, 0x03},
	)

	got, err := parseDeviceInfo(encoded)
	if err != nil {
		t.Fatalf("parseDeviceInfo() error = %v", err)
	}
	if got.FormFactor() != FormfactorUSBCKeychain {
		t.Errorf("FormFactor() = 0x%02x, want 0x03", got.FormFactor())
	}
}

func TestParseDeviceInfoRejectsMalformedData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		encoded []byte
	}{
		{name: "empty response", encoded: []byte{}},
		{name: "declared length too short", encoded: []byte{0x00, 0x04, 0x01, 0x03}},
		{name: "declared length too long", encoded: []byte{0x04, 0x04, 0x01, 0x03}},
		{name: "truncated header", encoded: []byte{0x01, 0x04}},
		{name: "truncated value", encoded: []byte{0x03, 0x04, 0x02, 0x03}},
		{
			name:    "serial wrong length",
			encoded: encodeManagementTLVs([]byte{0x02, 0x03, 0x01, 0x02, 0x03}),
		},
		{
			name:    "firmware wrong length",
			encoded: encodeManagementTLVs([]byte{0x05, 0x02, 0x05, 0x07}),
		},
		{
			name:    "form factor wrong length",
			encoded: encodeManagementTLVs([]byte{0x04, 0x02, 0x03, 0x04}),
		},
		{
			name:    "supported capabilities wrong length",
			encoded: encodeManagementTLVs([]byte{0x01, 0x01, 0x3f}),
		},
		{
			name:    "enabled capabilities wrong length",
			encoded: encodeManagementTLVs([]byte{0x03, 0x01, 0x3f}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseDeviceInfo(tt.encoded); err == nil {
				t.Fatal("parseDeviceInfo() error = nil, want malformed response error")
			}
		})
	}
}

func TestParseDeviceInfoRejectsDuplicateTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tag  byte
	}{
		{name: "known tag", tag: 0x04},
		{name: "unknown tag", tag: 0x7f},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded := encodeManagementTLVs(
				[]byte{tt.tag, 0x01, 0x01},
				[]byte{tt.tag, 0x01, 0x02},
			)
			if _, err := parseDeviceInfo(encoded); err == nil {
				t.Fatal("parseDeviceInfo() error = nil, want duplicate tag error")
			}
		})
	}
}

func TestReadDeviceInfoSendsOnlyReadConfig(t *testing.T) {
	t.Parallel()

	encoded := encodeManagementTLVs([]byte{0x04, 0x01, 0x03})
	tx := &recordingTransmitter{
		commands:  []apdu{},
		responses: [][]byte{nil, encoded, nil},
		errors:    []error{},
	}

	got, err := readDeviceInfo(tx)
	if err != nil {
		t.Fatalf("readDeviceInfo() error = %v", err)
	}
	if got.FormFactor() != FormfactorUSBCKeychain {
		t.Errorf("FormFactor() = 0x%02x, want 0x03", got.FormFactor())
	}

	want := []apdu{
		{instruction: insSelectApplication, param1: 0x04, data: aidManagement[:]},
		{instruction: insReadConfig},
		{instruction: insSelectApplication, param1: 0x04, data: aidPIV[:]},
	}
	if !reflect.DeepEqual(tx.commands, want) {
		t.Errorf("commands = %#v, want %#v", tx.commands, want)
	}
	for _, command := range tx.commands {
		isWrite := command.instruction == insWriteConfig
		isDataBearingRead := command.instruction == insReadConfig && len(command.data) != 0
		if isWrite || isDataBearingRead {
			t.Errorf("read operation sent mutating or data-bearing command: %#v", command)
		}
	}
}

func TestReadDeviceInfoRestoresPIVAfterMalformedResponse(t *testing.T) {
	t.Parallel()

	tx := &recordingTransmitter{
		commands:  []apdu{},
		responses: [][]byte{nil, {0x01, 0x04}, nil},
		errors:    []error{},
	}

	if _, err := readDeviceInfo(tx); err == nil {
		t.Fatal("readDeviceInfo() error = nil, want malformed response error")
	}
	if len(tx.commands) != 3 {
		t.Fatalf("command count = %d, want 3", len(tx.commands))
	}
	last := tx.commands[len(tx.commands)-1]
	if last.instruction != insSelectApplication || !bytes.Equal(last.data, aidPIV[:]) {
		t.Errorf("last command = %#v, want PIV applet selection", last)
	}
}

func TestReadDeviceInfoReportsPIVRestoreFailure(t *testing.T) {
	t.Parallel()

	encoded := encodeManagementTLVs([]byte{0x04, 0x01, 0x03})
	tx := &recordingTransmitter{
		commands:  []apdu{},
		responses: [][]byte{nil, encoded, nil},
		errors:    []error{nil, nil, errors.New("restore failed")},
	}

	if _, err := readDeviceInfo(tx); err == nil {
		t.Fatal("readDeviceInfo() error = nil, want PIV restore error")
	}
}

type recordingTransmitter struct {
	commands  []apdu
	responses [][]byte
	errors    []error
}

func (t *recordingTransmitter) Transmit(command apdu) ([]byte, error) {
	t.commands = append(t.commands, command)
	var err error
	if len(t.errors) != 0 {
		err = t.errors[0]
		t.errors = t.errors[1:]
	}
	if len(t.responses) == 0 {
		return nil, err
	}
	response := t.responses[0]
	t.responses = t.responses[1:]
	return response, err
}

func encodeManagementTLVs(tlvs ...[]byte) []byte {
	payload := bytes.Join(tlvs, nil)
	return append([]byte{byte(len(payload))}, payload...)
}
