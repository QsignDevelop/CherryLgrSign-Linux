package main

import "sync/atomic"

type pageStats struct {
	HomePage atomic.Uint64
	Appinfo  atomic.Uint64
	Sign     atomic.Uint64
}

var visitStats pageStats

func snapshotPageStats() map[string]uint64 {
	return map[string]uint64{
		"HomePage": visitStats.HomePage.Load(),
		"Appinfo":  visitStats.Appinfo.Load(),
		"Sign":     visitStats.Sign.Load(),
	}
}
