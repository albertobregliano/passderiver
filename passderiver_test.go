// Packet passderiver derives passwords instead of storing them.
// The password will always contain at least a digit a lowercase and an
// uppercase alpha rune and a symbol. All characters are utf8.
// Password length can be chosen from 8 to 21 characters.
// Renewing passwords for the same website can be done chosing a different num.

package passderiver_test

import (
	"testing"

	"github.com/albertobregliano/passderiver"
)

func TestDerive(t *testing.T) {
	type args struct {
		userKey []byte
		site    string
		num     int
		length  int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"derive1", args{userKey: []byte("userkey"), site: "openbsd.org"}, "Na#BSJ]8"},
		{"derive2", args{userKey: []byte("userkey"), site: "openbsd.org", num: 2}, "WZgk={9O"},
		{"derive3", args{userKey: []byte("userkey"), site: "openbsd.org", num: 2, length: 12}, ">DOFHvp6#WkG"},
		{"derive4", args{userKey: []byte("userkey"), site: "openbsd.org", length: 16}, "IGBW9(/S+5K[4(gu"},
		{"derive5", args{userKey: []byte("userkey"), site: "openbsd.org", length: 21}, "4g?IapKr9-SBE}O1/3+WF"},
		{"derive6", args{userKey: []byte("userkey"), site: "openbsd.org", length: 1000}, "4g?IapKr9-SBE}O1/3+WF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := passderiver.Derive(tt.args.userKey, tt.args.site, tt.args.num, tt.args.length); got != tt.want {
				t.Errorf("Derive() = %v, want %v", got, tt.want)
			}
		})
	}
}
