package main

import (
	"fmt"
	"github.com/pkg/errors"
	"gopkg.in/urfave/cli.v2"
	"os"
)

func main() {
	app := &cli.App{}
	app.Name = "inode"
	app.Commands = []*cli.Command{
		{
			Name:        "init",
			Action:      func(ctx *cli.Context) error {
				inode, err := New(ctx.String("interface"),
					ctx.String("username"),
					ctx.String("password"),
					ctx.String("version"),
				)
				if err != nil {
					return errors.Wrap(err, "Inode.new")
				}
				err = inode.Start()
				if err != nil {
					return errors.Wrap(err, "Inode.run")
				}
				return nil
			},
			Flags:[]cli.Flag{
				&cli.StringFlag{
					Name:  "version",
					Value: "V7.30-0515",
				},
				&cli.BoolFlag{
					Name:  "ip",
					Usage: "发送IP地址",
					Value: false,
				},
				&cli.StringFlag{
					Name:    "username",
					Usage:   "username",
					Aliases: []string{"U"},
				},
				&cli.StringFlag{
					Name:    "password",
					Usage:   "password",
					Aliases: []string{"P"},
				},
				&cli.StringFlag{
					Name:    "interface",
					Usage:   "interface",
					Value:   "eth0",
					Aliases: []string{"I"},
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
