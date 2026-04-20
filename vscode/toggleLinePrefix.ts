#!/usr/bin/env -S deno run --allow-all --no-lock
// deno-lint-ignore no-import-prefix
import { parseArgs } from 'jsr:@std/cli@1.0.28/parse-args';

const args = parseArgs(Deno.args, {
	string: ['file', 'line', 'prefix'],
});

const filePath = args.file;
const lineNumber = Number(args.line);
const prefix = args.prefix;

if (!filePath || !Number.isInteger(lineNumber) || lineNumber < 1 || !prefix) {
	console.error(
		'Usage: toggleLinePrefix.ts --file <path> --line <number> --prefix <string>',
	);
	Deno.exit(1);
}

try {
	const content = await Deno.readTextFile(filePath);
	const lines = content.split('\n');

	if (lineNumber > lines.length) {
		console.error(
			`Line ${lineNumber} exceeds file length (${lines.length}).`,
		);
		Deno.exit(1);
	}

	// TODO: Make it language agnostic.
	let line = lines[lineNumber - 1];

	if (line.startsWith(prefix)) line = line.slice(prefix.length);
	else line = prefix + line;

	lines[lineNumber - 1] = line;
	await Deno.writeTextFile(filePath, lines.join('\n'));
} catch (error) {
	console.error('Error:', error instanceof Error ? error.message : error);
	Deno.exit(1);
}
