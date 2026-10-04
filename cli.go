package uauthn

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

const AddUsage = "add [--password PASSWORD] [--reset] USERNAME"

type AddOptions struct {
	User     string
	Password string
	HasPass  bool
	Reset    bool
	Passwd   string
}

func ParseAddArgs(args []string, extra map[string]*string) (AddOptions, error) {
	var o AddOptions
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := strings.Cut(a, "=")
		takeValue := func() (string, error) {
			if hasVal {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", name)
			}
			i++
			return args[i], nil
		}
		switch {
		case name == "--password" || name == "-password":
			v, err := takeValue()
			if err != nil {
				return o, err
			}
			o.Password, o.HasPass = v, true
		case a == "--reset" || a == "-reset":
			o.Reset = true
		case extra[strings.TrimLeft(name, "-")] != nil && strings.HasPrefix(name, "-"):
			v, err := takeValue()
			if err != nil {
				return o, err
			}
			*extra[strings.TrimLeft(name, "-")] = v
		case strings.HasPrefix(a, "-") && a != "-":
			return o, fmt.Errorf("unknown option %s", a)
		case o.User == "":
			o.User = a
		default:
			return o, fmt.Errorf("unexpected argument %q", a)
		}
	}
	if o.User == "" {
		return o, errors.New("missing USERNAME")
	}
	return o, ValidUserName(o.User)
}

func RunAdd(o AddOptions, out io.Writer) error {
	if !o.HasPass {
		p, err := readNewPassword(out)
		if err != nil {
			return err
		}
		o.Password = p
	}
	if o.Password == "" {
		return errors.New("empty password")
	}
	hash, err := HashPassword(o.Password)
	if err != nil {
		return err
	}
	created, err := NewUsers(o.Passwd).SetPassword(o.User, hash, o.Reset)
	if err != nil {
		return err
	}
	switch {
	case created:
		fmt.Fprintf(out, "added %s to %s\n", o.User, o.Passwd)
	case o.Reset:
		fmt.Fprintf(out, "reset %s in %s\n", o.User, o.Passwd)
	default:
		fmt.Fprintf(out, "updated the password of %s in %s\n", o.User, o.Passwd)
	}
	return nil
}

func readNewPassword(out io.Writer) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("standard input is not a terminal; use --password")
	}
	fmt.Fprint(out, "Password: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	fmt.Fprint(out, "Confirm password: ")
	p2, err := term.ReadPassword(fd)
	fmt.Fprintln(out)
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", errors.New("passwords do not match")
	}
	return string(p1), nil
}
