#!/bin/bash
echo "read-only text"
printf '%s\n' "synthetic output" > example-output.txt
rm -- example-output.txt
