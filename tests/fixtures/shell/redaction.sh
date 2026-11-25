#!/bin/bash
PASSWORD=example-fixture-env custom --token 'example-fixture-token'
bash -c 'custom --token example-fixture-nested'
custom https://example:example-fixture-uri@example.invalid
