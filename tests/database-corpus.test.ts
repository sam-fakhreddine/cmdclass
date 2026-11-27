import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyProvider } from "../src/providers.ts";
import type { Classification } from "../src/report.ts";

type Case = readonly [readonly string[], Classification];

const sql: readonly Case[] = [
  [["SELECT * FROM example"], "UNKNOWN"],
  [["SHOW TABLES"], "UNKNOWN"],
  [["DESCRIBE example"], "UNKNOWN"],
  [["EXPLAIN SELECT * FROM example"], "UNKNOWN"],
  [["DROP TABLE example"], "MUTATING"],
  [["DELETE FROM example"], "MUTATING"],
  [["TRUNCATE TABLE example"], "MUTATING"],
  [["INSERT INTO example VALUES (1)"], "MUTATING"],
  [["UPDATE example SET name='x'"], "MUTATING"],
  [["CREATE TABLE example (id INT)"], "MUTATING"],
  [[""], "UNKNOWN"],
  [["\\dt"], "UNKNOWN"],
  [["\\l"], "UNKNOWN"],
  [["\\! echo example"], "UNKNOWN"],
  [["\\copy example to 'example.out'"], "UNKNOWN"],
  [["VACUUM"], "UNKNOWN"],
  [["select * from example"], "UNKNOWN"],
  [["DrOp table example"], "MUTATING"],
];

const clients: Record<string, readonly Case[]> = {
  psql: [
    [[], "UNKNOWN"], [["--help"], "UNKNOWN"], [["--version"], "UNKNOWN"],
    [["-l"], "UNKNOWN"], [["--list"], "UNKNOWN"],
    [["-c", "SELECT * FROM example"], "UNKNOWN"], [["-c", "DROP TABLE example"], "MUTATING"],
    [["-cSELECT 1"], "UNKNOWN"], [["-cDROP TABLE example"], "UNKNOWN"],
    [["-f", "example.sql"], "UNKNOWN"], [["--file", "example.sql"], "UNKNOWN"],
    [["-h", "example.invalid", "-U", "example", "example"], "UNKNOWN"],
  ],
  mysql: [
    [[], "UNKNOWN"], [["--help"], "UNKNOWN"],
    [["-e", "SELECT * FROM example"], "UNKNOWN"], [["-e", "DROP TABLE example"], "MUTATING"],
    [["--execute", "SELECT 1"], "UNKNOWN"], [["--execute", "DELETE FROM example"], "MUTATING"],
    [["-eSELECT 1"], "UNKNOWN"], [["-eDROP TABLE example"], "UNKNOWN"],
    [["--init-command", "DELETE FROM example"], "UNKNOWN"], [["--init-command=DELETE FROM example"], "UNKNOWN"],
  ],
  mongosh: [
    [[], "UNKNOWN"], [["--help"], "UNKNOWN"], [["--version"], "UNKNOWN"],
    [["--eval", "db.example.find()"], "UNKNOWN"], [["--eval", "db.example.count()"], "UNKNOWN"],
    [["--eval", "db.example.drop()"], "UNKNOWN"], [["--eval", "db.example.deleteMany({})"], "UNKNOWN"],
    [["--eval", "db.example.insertOne({name:'x'})"], "UNKNOWN"], [["--eval", "db.runCommand({example:1})"], "UNKNOWN"],
    [["--file", "example.js"], "UNKNOWN"], [["-f", "example.js"], "UNKNOWN"],
  ],
  "redis-cli": [
    [[], "UNKNOWN"], [["--help"], "UNKNOWN"],
    [["GET", "example"], "UNKNOWN"], [["KEYS", "*"], "UNKNOWN"], [["INFO"], "UNKNOWN"], [["PING"], "READ-ONLY"],
    [["SET", "example", "new-value"], "MUTATING"], [["DEL", "example"], "MUTATING"],
    [["FLUSHALL"], "MUTATING"], [["FLUSHDB"], "MUTATING"],
    [["CONFIG", "GET", "maxmemory"], "UNKNOWN"], [["CONFIG", "SET", "maxmemory", "100mb"], "UNKNOWN"],
    [["-h", "example.invalid", "-p", "6379", "GET", "example"], "UNKNOWN"], [["SCAN", "0"], "UNKNOWN"],
  ],
};

test("DeployShield database scenarios do not grant read-only status to opaque queries", () => {
  const check = (provider: string, args: readonly string[], expected: Classification) =>
    assert.equal(classifyProvider(provider, args)?.class, expected, JSON.stringify([provider, ...args]));
  for (const [[statement], expected] of sql) check("psql", ["-X", "-c", statement], expected);
  for (const [provider, rows] of Object.entries(clients)) {
    for (const [args, expected] of rows) check(provider, args, expected);
  }
});
