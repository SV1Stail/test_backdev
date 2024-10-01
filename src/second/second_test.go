package second_test

import (
	"log"
	"testing"

	"github.com/SV1Stail/test_backdev/second"
)

func TestIsEmpty_1(t *testing.T) {
	tokens := second.Tokens{
		AToken: "",
		RToken: "asd",
	}
	if err := tokens.IsEmpty(); err == nil {
		log.Fatal("expected error")
	}
}
func TestIsEmpty_2(t *testing.T) {
	tokens := second.Tokens{
		AToken: "asd",
		RToken: "",
	}
	if err := tokens.IsEmpty(); err == nil {
		log.Fatal("expected error")
	}
}
func TestIsEmpty_3(t *testing.T) {
	tokens := second.Tokens{
		AToken: "asd",
		RToken: "asd",
	}
	if err := tokens.IsEmpty(); err != nil {
		log.Fatal("UNexpected error")
	}
}
