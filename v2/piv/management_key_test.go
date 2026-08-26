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

import "testing"

func TestManagementKeyAlgorithmMapping(t *testing.T) {
	tests := []struct {
		name    string
		alg     ManagementKeyAlgorithm
		wantAlg byte
		wantLen int
	}{
		{"3DES", ManagementKeyAlgorithm3DES, alg3DES, 24},
		{"AES128", ManagementKeyAlgorithmAES128, algAES128, 16},
		{"AES192", ManagementKeyAlgorithmAES192, algAES192, 24},
		{"AES256", ManagementKeyAlgorithmAES256, algAES256, 32},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.alg.alg()
			if !ok {
				t.Fatalf("alg() ok = false, want true")
			}
			if got != tc.wantAlg {
				t.Errorf("alg() = 0x%02x, want 0x%02x", got, tc.wantAlg)
			}
			if l := managementKeyLengthMap[got]; l != tc.wantLen {
				t.Errorf("managementKeyLengthMap[0x%02x] = %d, want %d", got, l, tc.wantLen)
			}
		})
	}
	if _, ok := ManagementKeyAlgorithm(0).alg(); ok {
		t.Errorf("alg() ok = true for zero value, want false")
	}
}

func TestSetManagementKeyWithAlgorithmValidation(t *testing.T) {
	yk := &YubiKey{}
	if err := yk.SetManagementKeyWithAlgorithm(nil, make([]byte, 16), ManagementKeyAlgorithm3DES); err == nil {
		t.Errorf("SetManagementKeyWithAlgorithm(16-byte key, 3DES) = nil, want length error")
	}
	if err := yk.SetManagementKeyWithAlgorithm(nil, make([]byte, 24), ManagementKeyAlgorithm(42)); err == nil {
		t.Errorf("SetManagementKeyWithAlgorithm(alg=42) = nil, want unsupported algorithm error")
	}
}
