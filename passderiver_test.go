// Packet passderiver derives passwords instead of storing them.
// The password will always contain at least a digit a lowercase and an
// uppercase alpha rune and a symbol. All characters are utf8.
// Password length can be chosen from 8 to 21 characters.
// Renewing passwords for the same website can be done chosing a different num.

package passderiver

import "testing"

func TestDerive(t *testing.T) {
	type args struct {
		userSecret string
		site       string
		num        int
		length     int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"derive1", args{userSecret: "me" + "supersecret", site: "openbsd.org"}, "po(B81=8"},
		{"derive2", args{userSecret: "me" + "supersecret", site: "openbsd.org", num: 2}, "<JL9y,Gl"},
		{"derive3", args{userSecret: "me" + "supersecret", site: "openbsd.org", num: 2, length: 12}, "mL{o)Gy4hHQr"},
		{"derive4", args{userSecret: "you" + "supersecret2", site: "openbsd.org", length: 16}, "/wTJ0q/j[1:Q+VuT"},
		{"derive5", args{userSecret: "her" + "supersecret3", site: "openbsd.org", length: 21}, "SjY04=.nrqVTb;TcSjIk3"},
		{"derive6", args{userSecret: "her" + "supersecret3", site: "openbsd.org", length: 1000}, "SjY04=.nrqVTb;TcSjIk3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Derive(tt.args.userSecret, tt.args.site, tt.args.num, tt.args.length); got != tt.want {
				t.Errorf("Derive() = %v, want %v", got, tt.want)
			}
		})
	}
}
