package sliver

import (
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

func TestParseShellcodeEncoderValid(t *testing.T) {
	tests := []struct {
		in   string
		want clientpb.ShellcodeEncoder
	}{
		{"", clientpb.ShellcodeEncoder_NONE},
		{"NONE", clientpb.ShellcodeEncoder_NONE},
		{"none", clientpb.ShellcodeEncoder_NONE},
		{"None", clientpb.ShellcodeEncoder_NONE},
		{"SHIKATA_GA_NAI", clientpb.ShellcodeEncoder_SHIKATA_GA_NAI},
		{"shikata_ga_nai", clientpb.ShellcodeEncoder_SHIKATA_GA_NAI},
		{"SGN", clientpb.ShellcodeEncoder_SHIKATA_GA_NAI},
		{"sgn", clientpb.ShellcodeEncoder_SHIKATA_GA_NAI},
		{"XOR", clientpb.ShellcodeEncoder_XOR},
		{"xor", clientpb.ShellcodeEncoder_XOR},
		{"XOR_DYNAMIC", clientpb.ShellcodeEncoder_XOR_DYNAMIC},
		{"xor_dynamic", clientpb.ShellcodeEncoder_XOR_DYNAMIC},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseShellcodeEncoder(tc.in)
			if err != nil {
				t.Fatalf("parseShellcodeEncoder(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("parseShellcodeEncoder(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseShellcodeEncoderInvalid(t *testing.T) {
	invalid := []string{"GARBAGE", "RC4", "BASE64", "aes", "shikata", "xor-dynamic"}
	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := parseShellcodeEncoder(name)
			if err == nil {
				t.Fatalf("parseShellcodeEncoder(%q) expected error for unknown name, got nil", name)
			}
		})
	}
}
