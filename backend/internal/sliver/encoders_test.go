package sliver

import (
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

func TestTrafficEncoderTestsToView_Nil(t *testing.T) {
	v := trafficEncoderTestsToView("enc.wasm", nil)
	if v == nil || v.Name != "enc.wasm" || !v.Passed {
		t.Fatalf("nil tests: %+v", v)
	}
}

func TestTrafficEncoderTestsToView_Failed(t *testing.T) {
	v := trafficEncoderTestsToView("enc.wasm", &clientpb.TrafficEncoderTests{
		Encoder:       &clientpb.TrafficEncoder{Wasm: &commonpb.File{Name: "from-server.wasm"}},
		TotalTests:    2,
		TotalDuration: 12,
		Tests: []*clientpb.TrafficEncoderTest{
			{Name: "roundtrip", Completed: true, Success: true, Duration: 5},
			{Name: "fuzz", Completed: true, Success: false, Duration: 7, Err: "mismatch"},
		},
	})
	if v.Passed {
		t.Fatal("expected failed")
	}
	if v.Name != "from-server.wasm" || len(v.Tests) != 2 || v.Tests[1].Err != "mismatch" {
		t.Fatalf("%+v", v)
	}
}

func TestAddTrafficEncoderRequiresName(t *testing.T) {
	c := &Client{}
	if _, err := c.AddTrafficEncoder("", []byte{1}, true); err == nil {
		t.Fatal("empty name")
	}
	if _, err := c.AddTrafficEncoder("x.wasm", nil, true); err == nil {
		t.Fatal("empty wasm")
	}
	if err := c.RemoveTrafficEncoder(""); err == nil {
		t.Fatal("empty remove")
	}
}
