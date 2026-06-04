package singbox

import (
	"context"
	"fmt"

	sing_box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// CreateBox creates a minimal sing-box Box with a single outbound.
// The Box handles all protocol encryption/transport internally via sing-box.
func CreateBox(outboundOpt option.Outbound) (*sing_box.Box, adapter.Outbound, error) {
	ctx := include.Context(context.Background())

	options := sing_box.Options{
		Context: ctx,
		Options: option.Options{
			Log: &option.LogOptions{
				Level:        "warn",
				Disabled:     false,
				DisableColor: true,
			},
			Outbounds: []option.Outbound{
				outboundOpt,
			},
			Route: &option.RouteOptions{
				AutoDetectInterface: false,
				FindProcess:         false,
			},
		},
	}

	box, err := sing_box.New(options)
	if err != nil {
		return nil, nil, fmt.Errorf("sing_box.New: %w", err)
	}

	// Box.Start() handles all lifecycle stages internally (including preStart).
	err = box.Start()
	if err != nil {
		box.Close()
		return nil, nil, fmt.Errorf("box.Start: %w", err)
	}

	outbound, ok := box.Outbound().Outbound(outboundOpt.Tag)
	if !ok {
		box.Close()
		return nil, nil, fmt.Errorf("outbound %q not found", outboundOpt.Tag)
	}

	return box, outbound, nil
}
