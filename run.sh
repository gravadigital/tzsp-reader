#!/bin/bash

export DISPLAY=:0
gnome-terminal -e "python tzsp-reader.py" --full-screen --zoom=1.5 --hide-menubar
