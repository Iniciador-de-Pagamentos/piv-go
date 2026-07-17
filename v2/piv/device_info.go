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
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	tagUSBSupported = 0x01
	tagSerial       = 0x02
	tagUSBEnabled   = 0x03
	tagFormFactor   = 0x04
	tagVersion      = 0x05
)

// Capability is a bit mask of applications exposed by a YubiKey interface.
//
// See https://developers.yubico.com/yubikey-manager/Config_Reference.html#_list_of_capabilities.
type Capability uint16

// YubiKey application capability bits.
const (
	CapabilityOTP     Capability = 0x0001
	CapabilityU2F     Capability = 0x0002
	CapabilityCCID    Capability = 0x0004
	CapabilityOpenPGP Capability = 0x0008
	CapabilityPIV     Capability = 0x0010
	CapabilityOATH    Capability = 0x0020
	CapabilityHSMAuth Capability = 0x0100
	CapabilityFIDO2   Capability = 0x0200
)

// DeviceInfo is immutable information reported by the YubiKey management
// applet. Its accessors return values, so callers cannot modify the parsed
// device state.
type DeviceInfo struct {
	serial                   uint32
	version                  Version
	formFactor               Formfactor
	supportedUSBCapabilities Capability
	enabledUSBCapabilities   Capability
}

// Serial returns the YubiKey serial number, or zero when the device does not
// report one.
func (d DeviceInfo) Serial() uint32 {
	return d.serial
}

// Version returns the YubiKey firmware version.
func (d DeviceInfo) Version() Version {
	return d.version
}

// FormFactor returns the physical form factor reported by the YubiKey.
func (d DeviceInfo) FormFactor() Formfactor {
	return d.formFactor
}

// IsFIPS reports whether the form-factor FIPS bit is set.
func (d DeviceInfo) IsFIPS() bool {
	return uint8(d.formFactor)&0x80 != 0
}

// SupportedUSBCapabilities returns the applications supported over USB.
func (d DeviceInfo) SupportedUSBCapabilities() Capability {
	return d.supportedUSBCapabilities
}

// EnabledUSBCapabilities returns the applications currently enabled over USB.
func (d DeviceInfo) EnabledUSBCapabilities() Capability {
	return d.enabledUSBCapabilities
}

// DeviceInfo returns information and USB capabilities reported by the YubiKey
// management applet.
func (yk *YubiKey) DeviceInfo() (DeviceInfo, error) {
	return readDeviceInfo(yk.tx)
}

func readDeviceInfo(tx apduTransmitter) (info DeviceInfo, err error) {
	if err := ykSelectApplication(tx, aidManagement[:]); err != nil {
		return DeviceInfo{}, fmt.Errorf("selecting management applet: %w", err)
	}
	defer func() {
		if restoreErr := ykSelectApplication(tx, aidPIV[:]); restoreErr != nil {
			info = DeviceInfo{}
			err = errors.Join(err, fmt.Errorf("restoring PIV applet: %w", restoreErr))
		}
	}()

	response, err := tx.Transmit(apdu{instruction: insReadConfig})
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("reading device info: %w", err)
	}
	info, err = parseDeviceInfo(response)
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("parsing device info: %w", err)
	}
	return info, nil
}

func parseDeviceInfo(encoded []byte) (DeviceInfo, error) {
	if len(encoded) == 0 {
		return DeviceInfo{}, fmt.Errorf("response is empty")
	}
	if got, want := len(encoded)-1, int(encoded[0]); got != want {
		return DeviceInfo{}, fmt.Errorf("response length is %d, declared %d", got, want)
	}

	var info DeviceInfo
	payload := encoded[1:]
	seen := make(map[byte]struct{})
	for len(payload) > 0 {
		if len(payload) < 2 {
			return DeviceInfo{}, fmt.Errorf("truncated TLV header")
		}
		tag := payload[0]
		length := int(payload[1])
		payload = payload[2:]
		if len(payload) < length {
			return DeviceInfo{}, fmt.Errorf("tag 0x%02x value is truncated", tag)
		}
		if _, ok := seen[tag]; ok {
			return DeviceInfo{}, fmt.Errorf("duplicate tag 0x%02x", tag)
		}
		seen[tag] = struct{}{}
		value := payload[:length]
		payload = payload[length:]

		switch tag {
		case tagUSBSupported:
			if len(value) != 2 {
				return DeviceInfo{}, invalidDeviceInfoLength(tag, len(value), 2)
			}
			info.supportedUSBCapabilities = Capability(binary.BigEndian.Uint16(value))
		case tagSerial:
			if len(value) != 4 {
				return DeviceInfo{}, invalidDeviceInfoLength(tag, len(value), 4)
			}
			info.serial = binary.BigEndian.Uint32(value)
		case tagUSBEnabled:
			if len(value) != 2 {
				return DeviceInfo{}, invalidDeviceInfoLength(tag, len(value), 2)
			}
			info.enabledUSBCapabilities = Capability(binary.BigEndian.Uint16(value))
		case tagFormFactor:
			if len(value) != 1 {
				return DeviceInfo{}, invalidDeviceInfoLength(tag, len(value), 1)
			}
			info.formFactor = Formfactor(value[0])
		case tagVersion:
			if len(value) != 3 {
				return DeviceInfo{}, invalidDeviceInfoLength(tag, len(value), 3)
			}
			info.version = Version{
				Major: int(value[0]),
				Minor: int(value[1]),
				Patch: int(value[2]),
			}
		}
	}

	return info, nil
}

func invalidDeviceInfoLength(tag byte, got, want int) error {
	return fmt.Errorf("tag 0x%02x has length %d, want %d", tag, got, want)
}
