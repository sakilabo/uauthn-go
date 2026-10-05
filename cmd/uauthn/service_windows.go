package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "uauthn"

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type service struct {
	log     *eventlog.Log
	dataDir string
}

func (s *service) logf(format string, args ...any) {
	if s.log != nil {
		s.log.Info(1, fmt.Sprintf(format, args...))
	}
}

func runService() error {
	dir, _, err := parseDataDir(os.Args[1:])
	if err != nil {
		return err
	}
	el, _ := eventlog.Open(serviceName)
	s := &service{log: el, dataDir: dir}
	if el != nil {
		defer el.Close()
	}
	return svc.Run(serviceName, s)
}

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- listen(ctx, "", s.dataDir, s.logf) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-errc
				return false, 0
			}
		case err := <-errc:
			if err != nil {
				if s.log != nil {
					s.log.Error(1, err.Error())
				}
				return false, 1
			}
			return false, 0
		}
	}
}

func installService(dataDir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}
	var args []string
	if dataDir != "" {
		args = []string{"--data_dir", dataDir}
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "uauthn",
		Description: "Passkey and password authentication for reverse proxies",
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		s.Delete()
		return fmt.Errorf("event log source: %w", err)
	}
	fmt.Printf("installed service %s (%s)\n", serviceName, exe)
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		s.Control(svc.Stop)
		for i := 0; i < 50; i++ {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	eventlog.Remove(serviceName)
	fmt.Printf("removed service %s\n", serviceName)
	return nil
}
