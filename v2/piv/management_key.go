// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv

import "fmt"

// ManagementKeyAlgorithm represents the algorithm of a management key.
type ManagementKeyAlgorithm int

// Management key algorithms supported by this package.
const (
	ManagementKeyAlgorithm3DES ManagementKeyAlgorithm = iota + 1
	ManagementKeyAlgorithmAES128
	ManagementKeyAlgorithmAES192
	ManagementKeyAlgorithmAES256
)

func (a ManagementKeyAlgorithm) alg() (byte, bool) {
	switch a {
	case ManagementKeyAlgorithm3DES:
		return alg3DES, true
	case ManagementKeyAlgorithmAES128:
		return algAES128, true
	case ManagementKeyAlgorithmAES192:
		return algAES192, true
	case ManagementKeyAlgorithmAES256:
		return algAES256, true
	}
	return 0, false
}

// SetManagementKeyWithAlgorithm updates the management key to a new key of
// the given algorithm. Unlike SetManagementKey, which infers the algorithm
// from the YubiKey version and key length, the algorithm is chosen by the
// caller. YubiKey 5.4.0 and later applets accept an explicit 3DES management
// key even though SetManagementKey would select AES for them.
func (yk *YubiKey) SetManagementKeyWithAlgorithm(oldKey, newKey []byte, alg ManagementKeyAlgorithm) error {
	algByte, ok := alg.alg()
	if !ok {
		return fmt.Errorf("unsupported management key algorithm: %d", alg)
	}
	if want := managementKeyLengthMap[algByte]; len(newKey) != want {
		return fmt.Errorf("invalid new management key length: %d bytes (expected %d)", len(newKey), want)
	}
	if err := ykAuthenticate(yk.tx, oldKey, yk.rand, yk.version); err != nil {
		return fmt.Errorf("authenticating with old key: %w", err)
	}
	cmd := apdu{
		instruction: insSetMGMKey,
		param1:      0xff,
		param2:      0xff,
		data: append([]byte{
			algByte, keyCardManagement, byte(len(newKey)),
		}, newKey...),
	}
	if _, err := yk.tx.Transmit(cmd); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}
