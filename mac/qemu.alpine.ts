#!/bin/sh
/* 2>/dev/null
die() { echo "$1" >&2; exit 1; }
[ $# -gt 1 ] && die "Too many arguments."
[ $# -eq 1 ] && [ "${1}" != "--uninstall" ] && die "Invalid argument: ${1}"
[ $# -eq 1 ] && FLAGS="--uninstall"

COMMIT_HASH=$(curl -fsSL "https://api.github.com/repos/navtoj/scripts/commits?per_page=1&sha=main&path=mac/qemu.alpine.ts" 2>/dev/null | jq -r '.[0].sha' 2>/dev/null)
[ -z "$COMMIT_HASH" ] && COMMIT_HASH="main"

[ -z "$FLAGS" ] && FLAGS="--install=$COMMIT_HASH"
SCRIPT_URL="https://raw.githubusercontent.com/navtoj/scripts/$COMMIT_HASH/mac/qemu.alpine.ts"
exec deno run --ext=ts --no-lock --allow-all --unstable-temporal "$SCRIPT_URL" "$FLAGS"
*/
// deno-lint-ignore-file no-import-prefix no-namespace
import { stripAnsiCodes } from 'jsr:@david/console-static-text@^0.3.0';
import $ from 'jsr:@david/dax@^0.44.2';
import { parseArgs, unicodeWidth } from 'jsr:@std/cli@^1.0.28';
import * as Ansi from 'jsr:@std/cli@^1.0.28/unstable-ansi';
import {
	bgBrightGreen,
	blue,
	bold,
	brightBlue,
	brightGreen,
	brightRed,
	brightYellow,
	green,
	red,
	white,
	yellow,
} from 'jsr:@std/fmt@^1.0.9/colors';
import { format } from 'jsr:@std/fmt@^1.0.9/duration';
import { copy, ensureDir, exists } from 'jsr:@std/fs@^1.0.22';
import { writeAll } from 'jsr:@std/io@^0.225/write-all';
import { dirname, extname, join } from 'jsr:@std/path@^1.1.4/posix';
import * as YAML from 'jsr:@std/yaml@^1.0.12';
import z from 'jsr:@zod/zod@^4.3.6';
import { homedir } from 'node:os';
import type { GetPathValue, Path } from 'npm:@clickbar/dot-diver@^2.0.0';
import type { RequireAtLeastOne } from 'npm:type-fest@^5.4.4';

namespace Static {
	export const enum OS {
		Version = '3.21',
		Arch = 'aarch64', // x86_64
		Firmware = 'uefi', // bios
		Image = `nocloud_alpine-${Version}.0-${Arch}-${Firmware}-cloudinit-r0.qcow2`,
		Url = `https://dl-cdn.alpinelinux.org/alpine/v${Version}/releases/cloud/${Image}`,
	}

	export const enum System {
		Name = 'qemu',
		User = 'alpine',
		CPUs = 4,
		Memory = '6G',
		DiskSize = '8G',
		Port = 4444,
	}

	export namespace CloudInit {
		function toYAML<Data extends Record<string, unknown>>(data: Data) {
			type YAML = `(YAML) ${Type.Union.join<keyof Data, ', '>}`;
			return YAML.stringify(data, { indent: 2, lineWidth: 120 }) as YAML;
		}
		export function MetaData() {
			const json = {
				'instance-id': `${System.Name}`,
				'local-hostname': `${System.Name}`,
			};
			return toYAML(json);
		}
		export function UserData(options: { PUBLIC_SSH_KEY: string }) {
			const json = {
				manage_etc_hosts: true,
				hostname: `${System.Name}`,
				users: [
					{
						name: `${System.User}`,
						groups: ['wheel', 'docker'],
						shell: '/bin/bash',
						doas: [`permit nopass ${System.User}`],
						lock_passwd: false,
						ssh_authorized_keys: [options.PUBLIC_SSH_KEY],
					},
				],
				ssh_pwauth: false,
				write_files: [
					{
						path: `/etc/ssh/sshd_config.d/50-${System.Name}-${System.User}.conf`,
						permissions: '0400',
						append: true,
						content: $.dedent`
						AllowTcpForwarding yes
						AuthenticationMethods publickey
						PermitRootLogin no
						ClientAliveInterval 60
						ClientAliveCountMax 3
					`,
					},
					{
						path: '/etc/motd',
						permissions: '0400',
					},
					{
						path: `/home/${System.User}/.local/bin/setup.sh`,
						permissions: '0755',
						owner: `${System.User}:${System.User}`,
						content: $.dedent`
						#!/bin/bash
						set -euo pipefail
						# TODO: Why do I need to manually change the shell?
						chsh --shell /bin/bash
						# git
						git config --global init.defaultBranch main
						git config --global pull.rebase true
						# docs.warp.dev
						echo -e '\\n\\n# Auto-Warpify\\n[[ "$-" == *i* ]] && printf '\\''\\eP$f{"hook": "SourcedRcFileForWarp", "value": { "shell": "bash", "uname": "'$(uname)'", "tmux": false }}\\x9c'\\'' ' >> ~/.bash_profile
						cat -s ~/.bash_profile | awk 'NF || p {print; p=1}' | sponge ~/.bash_profile
						# cleanup script
						rm "$0"`,
					},
					{
						path: `/home/${System.User}/.bashrc`,
						permissions: '0644',
						owner: `${System.User}:${System.User}`,
						append: true,
						content: $.dedent`
						# docs.astral.sh/uv
						eval "$(uv generate-shell-completion bash)"
						eval "$(uvx --generate-shell-completion bash)"`,
					},
				],
				resize_rootfs: true,
				growpart: {
					mode: 'auto',
					devices: ['/'],
				},
				packages: [
					// System
					'doas',
					'bash',
					'nano',
					'grep',
					'coreutils',
					'moreutils',
					// Connection
					'openssh',
					'tmux',
					// Development
					'netcat-openbsd',
					'curl',
					'wget',
					'git',
					'jq',
					'git-filter-repo',
					// Programming
					'sqlite-dev',
					'py3-uv',
					'nodejs',
					'npm',
					// Virtualization
					'docker-compose',
					'containerd',
					'kubectl',
					'docker',
				],
				bootcmd: [
					// Fix Node.js sqlite3 session symbol errors on Alpine 3.21
					// nodejs is compiled with sqlite session extension support but runtime
					// sqlite-libs lacks those symbols. sqlite-dev provides the complete library.
					'apk info -e sqlite-dev >/dev/null 2>&1 || apk add --no-cache sqlite-dev',
					// Add readline-dev for shell history support (arrow keys, editing)
					'apk info -e readline-dev >/dev/null 2>&1 || apk add --no-cache readline-dev',
				],
				runcmd: [
					// ssh
					'rc-update add sshd default',
					// cgroups
					'rc-update add cgroups default',
					'service cgroups start',
					// docker
					'rc-update add docker default',
					'service docker start',
					// containerd
					'rc-update add containerd default',
					'service containerd start',
					// python
					// 'pip3 install --break-system-packages fastapi uvicorn sqlalchemy jinja2 python-multipart httpx python-jose passlib bcrypt',
					// user setup
					`su -l ${System.User} -c '~/.local/bin/setup.sh;'`,
					// verify environment
					'echo "TODO: ~/.local/bin/verify-environment.sh"',
				],
				final_message: 'The instance is ready.',
			} as const;

			const yaml = toYAML(json);
			return [
				`#cloud-config`,
				`# yaml-language-server: $schema=https://raw.githubusercontent.com/canonical/cloud-init/main/cloudinit/config/schemas/versions.schema.cloud-config.json`,
				yaml,
			].join('\n') as typeof yaml;
		}
	}

	export enum Command {
		qemuSystem = `qemu-system-${OS.Arch}`,
		qemuImg = 'qemu-img',
		curl = 'curl',
		netcat = 'nc',
		xorriso = 'xorriso',
	}

	const Path = {
		Base: {
			_: `${System.Name}.${System.User}`,
			Log: 'vm.log',
			State: 'vm.json',
			LogArchive: '.vm.log',
			StateArchive: '.vm.json',
			Images: {
				_: 'images',
				Remote: `${OS.Image}`,
				Local: `${OS.Version}.qcow2`,
			},
			CloudInit: {
				_: 'cloudinit',
				Iso: 'cidata.iso',
				MetaData: 'meta-data',
				UserData: 'user-data',
			},
			ConfigSSH: 'ssh.config',
		},
	} as const;

	export function path<P extends Exclude<path.Key, `${string}._`>>(
		is: P,
	): path.Value<P> {
		const split = is.split('.');
		const route: string[] = [];
		let node: unknown = Path;
		for (const part of split) {
			node = (node as Record<string, unknown>)[part];
			route.push(
				typeof node === 'string'
					? node
					: (node as Record<'_', string>)._,
			);
		}
		return route.join('/') as path.Value<P>;
	}

	namespace path {
		export type Key<
			Offset extends Path<typeof Path, Offset, PathKeyOptions> = never,
			PathKeyOptions extends { depth: number } = { depth: 3 },
		> = Path<typeof Path, Offset, PathKeyOptions> & string;
		type ResultRaw<P extends string> = GetPathValue<typeof Path, P>;
		type Result<P extends Key<P>> =
			`${P}._` extends Extract<Key, `${string}._`>
				? ResultRaw<`${P}._`>
				: ResultRaw<P>;
		type Split<T extends string> = T extends `${infer Head}.${infer Tail}`
			? [Head, ...Split<Tail>]
			: [T];
		type Accumulate<
			T extends string[],
			Acc extends string = '',
		> = T extends []
			? []
			: T extends [infer First, ...infer Rest extends string[]]
				? [
						`${Acc extends '' ? '' : `${Acc & string}.`}${First & string}`,
						...Accumulate<
							Rest,
							`${Acc extends '' ? '' : `${Acc & string}.`}${First & string}`
						>,
					]
				: [];
		type Map<T extends Key[]> = T extends []
			? []
			: T extends [
						infer First extends Key<First>,
						...infer Rest extends Key[],
				  ]
				? [Result<First & string>, ...Map<Rest>]
				: [];
		type Join<T extends string[], Acc extends string = ''> = T extends []
			? Acc
			: T extends [infer First, ...infer Rest extends string[]]
				? Join<
						Rest,
						`${Acc extends '' ? '' : `${Acc & string}/`}${First & string}`
					>
				: never;
		export type Value<P extends Key> = Join<Map<Accumulate<Split<P>>>>;
	}
}

namespace Type {
	namespace Tuple {
		export type join<
			T extends unknown[],
			Separator extends string,
		> = T extends []
			? ''
			: T extends [infer F]
				? `${F & string}`
				: T extends [infer F, ...infer R]
					? `${F & string}${Separator}${join<R, Separator>}`
					: string;
	}
	export namespace Union {
		type ToIntersection<U> = (
			U extends unknown ? (k: U) => void : never
		) extends (k: infer I) => void
			? I
			: never;
		type LastItem<U> =
			ToIntersection<U extends unknown ? (x: U) => 0 : never> extends (
				x: infer L,
			) => 0
				? L
				: never;
		type ToTuple<U, Last = LastItem<U>> = [U] extends [never]
			? []
			: [...ToTuple<Exclude<U, Last>>, Last];

		export type join<U, Separator extends string> = Tuple.join<
			ToTuple<U>,
			Separator
		>;
	}

	/* Zod */

	export const State = z.object({
		pid: z.coerce.number().int().positive(),
		started: z.string().nonempty().nullable(),
	});
	export type State = z.infer<typeof State>;
}

/**
 * https://www.compart.com/en/unicode/block/U+2500
 */
namespace Block {
	const LightHorizontal = '─';
	const HeavyHorizontal = '━';
	const LightVertical = '│';
	const HeavyVertical = '┃';
	const LightDownandRight = '┌';
	const HeavyDownandRight = '┏';
	const LightDownandLeft = '┐';
	const HeavyDownandLeft = '┓';
	const LightUpandRight = '└';
	const HeavyUpandRight = '┗';
	const LightUpandLeft = '┘';
	const HeavyUpandLeft = '┛';
	const LightDownandHorizontal = '┬';
	const HeavyDownandHorizontal = '┳';
	const LightUpandHorizontal = '┴';
	const HeavyUpandHorizontal = '┻';
	const LightUp = '╵';
	const LightDown = '╷';
	const HeavyUp = '╹';
	const HeavyDown = '╻';

	export function boxed(
		input: string | string[],
		options: {
			bold: boolean;
		} = { bold: false },
	) {
		if (!Array.isArray(input)) input = [input];
		const topLeft = options.bold ? HeavyDownandRight : LightDownandRight;
		const topRight = options.bold ? HeavyDownandLeft : LightDownandLeft;
		const bottomLeft = options.bold ? HeavyUpandRight : LightUpandRight;
		const bottomRight = options.bold ? HeavyUpandLeft : LightUpandLeft;

		const horizontal = options.bold ? HeavyHorizontal : LightHorizontal;
		const vertical = options.bold ? HeavyVertical : LightVertical;
		const topMiddle = options.bold
			? HeavyDownandHorizontal
			: LightDownandHorizontal;
		const bottomMiddle = options.bold
			? HeavyUpandHorizontal
			: LightUpandHorizontal;

		let top = '';
		let middle = '';
		let bottom = '';

		for (const [index, line] of input.entries()) {
			const width = unicodeWidth(stripAnsiCodes(line)) + 2;
			const border = horizontal.repeat(width);
			top += border;
			middle += ` ${line} `;
			bottom += border;
			if (index + 1 === input.length) continue;
			top += topMiddle;
			middle += vertical;
			bottom += bottomMiddle;
		}

		return [
			`${topLeft}${top}${topRight}`,
			`${vertical}${middle}${vertical}`,
			`${bottomLeft}${bottom}${bottomRight}`,
		].join('\n');
	}

	export function lined(
		input: string | (string | string[])[],
		options: {
			bold: boolean;
		} = { bold: false },
	) {
		if (!Array.isArray(input)) input = [input];
		const vertical = options.bold ? HeavyVertical : LightVertical;
		return [
			options.bold ? HeavyDown : LightDown,
			input
				.map(line =>
					Array.isArray(line)
						? line.map(l => `${vertical} ${l}`).join('\n')
						: `${vertical} ${line}`,
				)
				.join(`\n${vertical}\n`),
			options.bold ? HeavyUp : LightUp,
		].join('\n');
	}
}

namespace Log {
	export function info(message: string, fmt: (str: string) => string = blue) {
		console.info(fmt(message));
	}
	export function warn(
		message: string,
		fmt: (str: string) => string = yellow,
	) {
		console.warn(fmt(message));
	}
	export function error(message: string, fmt: (str: string) => string = red) {
		console.error(fmt(message));
	}
	export function debug(
		message: string,
		fmt: (str: string) => string = bgBrightGreen,
	) {
		if (Deno.env.get('DEBUG') !== 'true') return;
		console.debug(fmt(message));
	}

	/**
	 * Exit the script with return code `0`.
	 * - `message`: The text to display.
	 */
	export function exit(
		message: Parameters<typeof info>[0],
		fmt?: Parameters<typeof info>[1],
	): never {
		if (message) info(message, fmt);
		Deno.exit();
	}
	/**
	 * Exit the script with return code `1`.
	 * - `message`: The error text to display.
	 */
	export function quit(
		message: Parameters<typeof error>[0],
		fmt?: Parameters<typeof error>[1],
	): never {
		if (message) error(message, fmt);
		Deno.exit(1);
	}
}

namespace Host {
	/**
	 * Get the content of a file in the user's home directory.
	 * @returns The file content, or `null` if the file does not exist.
	 */
	export async function file(options: {
		path: string;
	}): Promise<string | null>;
	/**
	 * Set the content of a file in the user's home directory.
	 *
	 * If the file does not exist, it will be created.
	 */
	export async function file(options: {
		path: string;
		value: string;
	}): Promise<void>;
	export async function file(options: {
		path: string;
		value?: string;
	}): Promise<string | null | void> {
		const path = join(homedir(), options.path);
		if (options?.value === undefined) {
			try {
				return await Deno.readTextFile(path);
			} catch (error) {
				if (!(error instanceof Deno.errors.NotFound)) throw error;
				return null;
			}
		}
		await ensureDir(dirname(path));
		await Deno.writeTextFile(path, options.value);
	}
	/** Manipulate a file in the user's home directory. */
	export namespace file {
		/**
		 * Prepend a line to a file if it doesn't already exist.
		 * - `false`: The line already exists; no change made.
		 * - `null`: Line added to an empty or new file.
		 * - `true`: Line added to the top of the file.
		 */
		export async function prepend(options: { path: string; line: string }) {
			const content = await file({ path: options.path });
			if (content?.startsWith(options.line)) return false;
			const cleaned = _.remove({
				content: content ?? '',
				match: line => line === options.line,
			});
			const lines = Array.isArray(cleaned)
				? cleaned
				: cleaned.split('\n');
			lines.unshift(options.line);
			await file({
				path: options.path,
				value: lines.join('\n'),
			});
			return !content?.trim() ? null : true;
		}
		/**
		 * Remove a line from a file if it exists.
		 * - `null`: The file is empty or does not exist.
		 * - `false`: No matching line found; no changes.
		 * - `true`: At least one matching line removed.
		 */
		export async function remove({
			path,
			match,
		}: {
			path: string;
			match: (line: string) => boolean;
		}) {
			const content = await file({ path });
			if (!content?.trim()) return null;
			const removed = _.remove({ content, match });
			if (Array.isArray(removed)) return false;
			await file({ path, value: removed });
			return true;
		}
		/* Helpers for manipulating file content. */
		namespace _ {
			/**
			 * Remove lines matching a condition from the content.
			 * - `string[]`: No matching lines found; no change made.
			 * - `string`: At least one matching line removed; the new content.
			 */
			export function remove(options: {
				content: string;
				match: (line: string) => boolean;
			}) {
				const lines = options.content.split('\n');
				const filtered = lines.filter(l => !options.match(l.trim()));
				if (filtered.length === lines.length) return filtered;
				return filtered.join('\n');
			}
		}
	}
}

namespace Zshrc {
	namespace prefix {
		export const scriptUrl =
			'https://raw.githubusercontent.com/navtoj/scripts/' as const;
		export const configLine =
			`alias ${Static.path('Base')}='deno run --ext=ts --no-lock --allow-all --unstable-temporal "` as const;
	}
	namespace suffix {
		export const scriptUrl = `/mac/${Static.path('Base')}.ts` as const;
		export const configLine = `"'` as const;
	}
	namespace zod {
		export const configLine = z
			.string()
			.regex(
				new RegExp(
					`^${RegExp.escape(prefix.configLine + prefix.scriptUrl)}[a-f0-9]{40}${RegExp.escape(suffix.scriptUrl + suffix.configLine)}$`,
					'i',
				),
			);
	}

	let ScriptUrl: string | null = null;
	export async function scriptUrl(hash?: string): Promise<string> {
		if (ScriptUrl) return ScriptUrl;
		if (!hash) {
			const json = await $.request(
				`https://api.github.com/repos/navtoj/scripts/commits?per_page=1&sha=main&path=mac/${Static.path('Base')}.ts`,
			).json();
			hash = z
				.string()
				.regex(/^[a-f0-9]{40}$/i, { error: 'Invalid script hash.' })
				.parse(json[0].sha);
		}
		ScriptUrl = `${prefix.scriptUrl}${hash}${suffix.scriptUrl}`;
		return ScriptUrl;
	}
	async function ConfigLine(): Promise<string> {
		return `${prefix.configLine}${await scriptUrl()}${suffix.configLine}`;
	}

	export const ConfigPath = `.zshrc` as const;
	export async function enable() {
		const configLine = await ConfigLine();
		const removed = await Host.file.remove({
			path: ConfigPath,
			match: line =>
				line !== configLine && zod.configLine.safeParse(line).success,
		});
		const added = await Host.file.prepend({
			path: ConfigPath,
			line: configLine,
		});
		return (added ?? true) ? (removed ? null : true) : false;
	}
	export async function disable() {
		const configLine = await ConfigLine();
		return await Host.file.remove({
			path: ConfigPath,
			match: line => line === configLine,
		});
	}
}

namespace SSH {
	export const Port = 2222 as const;
	const ConfigPath = `.ssh/config` as const;
	const ConfigLine =
		`Include ${Deno.cwd()}/${Static.path('Base.ConfigSSH')}` as const;

	export async function enable() {
		return await Host.file.prepend({
			path: ConfigPath,
			line: ConfigLine,
		});
	}
	export async function disable() {
		return await Host.file.remove({
			path: ConfigPath,
			match: line => line === ConfigLine,
		});
	}

	/**
	 * - `null`: No SSH listener found.
	 * - `false`: No established connections found.
	 * - `true`: At least one established connection found.
	 */
	export async function status(pid: number) {
		const output =
			await $`lsof +c0 -anP -i TCP:${Port} -c ${Static.Command.qemuSystem} -p ${pid}`
				.noThrow()
				.lines();
		const lines = output.slice(1); // -sTCP:LISTEN

		const listen = lines.filter(line => line.endsWith('(LISTEN)'));
		if (listen.length === 0) return null;
		if (listen.length !== 1) Log.quit(`Multiple SSH listeners found.`);

		const established = lines.filter(line =>
			line.endsWith('(ESTABLISHED)'),
		);
		return established.length !== 0;
	}
}

namespace Util {
	const encoder = new TextEncoder();
	export function toBinary(input: string) {
		return encoder.encode(input);
	}
	export function stdout(...input: string[]) {
		Deno.stdout.writeSync(toBinary(input.join('')));
	}

	/**
	 * Check if a process exists.
	 */
	export function exists(pid: number): boolean {
		try {
			Deno.kill(pid, 0);
			return true;
		} catch (error) {
			if (!(error instanceof Deno.errors.NotFound)) throw error;
		}
		return false;
	}

	/**
	 * Ensure a command is available on the system.
	 */
	export async function ensure(command: Static.Command, name?: string) {
		if (await $.commandExists(command)) return;
		const message = [command, name && `(${name})`, 'is not installed.'];
		Log.quit(message.filter(Boolean).join(' '));
	}

	/**
	 * - `fn`: The function to execute and time.
	 * - `args`: The arguments to pass to the function.
	 * @returns The execution duration (ms) and result.
	 */
	export async function time<
		F extends (...args: Parameters<F>) => ReturnType<F>,
	>(
		fn: F,
		...args: Parameters<F>
	): Promise<{
		result: Awaited<ReturnType<F>>;
		duration: number;
	}> {
		const start = performance.now();
		const result = await fn(...args);
		return {
			result: result as Awaited<ReturnType<typeof time>>['result'],
			duration: performance.now() - start,
		};
	}
}

namespace VM {
	async function WatchLog(
		match: (line: string) => boolean,
	): Promise<boolean> {
		const tail = new AbortController();
		const command = new Deno.Command('tail', {
			args: ['-f', '-n', '0', Static.path('Base.Log')],
			stdout: 'piped',
			stderr: 'null',
			stdin: 'null',
			detached: true,
			signal: tail.signal,
		}).spawn();

		const decoder = new TextDecoderStream();
		const reader = command.stdout.pipeThrough(decoder).getReader();

		let buffer = '';
		try {
			stream: while (true) {
				const { value: chunk, done } = await reader.read();
				if (done) break stream;

				buffer += chunk;
				const lines = buffer.split('\n');
				if (lines.some(match)) return true;
				buffer = lines.pop() ?? '';
			}
		} finally {
			await reader.cancel();
			tail.abort();
			await command.status;
		}
		return false;
	}

	/**
	 * - `Type.State`: The instance state.
	 * - `null`: No running instance found.
	 */
	async function State(): Promise<Type.State | null> {
		try {
			const text = await Deno.readTextFile(Static.path('Base.State'));
			const json: unknown = JSON.parse(text);
			const state = Type.State.parse(json);
			if (Util.exists(state.pid)) return state;
			await Deno.rename(
				Static.path('Base.State'),
				Static.path('Base.StateArchive'),
			);
		} catch (error) {
			if (
				!(
					error instanceof Deno.errors.NotFound ||
					error instanceof SyntaxError
				)
			)
				throw error;
		}
		return null;
	}
	namespace State {
		export function toBinary(state: Type.State) {
			const json = JSON.stringify(Type.State.parse(state), null, 2);
			return Util.toBinary(json);
		}
	}

	/**
	 * Find unknown instances running the local image.
	 */
	export async function unknown(): Promise<number[]> {
		const diskPath = Static.path('Base.Images.Local');
		const fileExists = await exists(diskPath, { isFile: true });
		if (!fileExists) return [];

		// pgrep -f ${Command.qemuSystem}
		const instances = Array.from(
			new Set(
				(
					await $`lsof -t ${diskPath}`.noThrow().quiet().lines()
				).flatMap(line => line.trim() || []),
			),
		);

		const state = await State();
		return instances.flatMap(i => {
			if (i.trim() === '') return [];
			const pid = Type.State.shape.pid.parse(i);
			if (state?.pid === pid) return [];
			return pid;
		});
	}

	/**
	 * - `undefined`: No instance found. (Offline)
	 * - `null`: The instance is starting. (Loading)
	 * - `false`: The instance is running. (Online)
	 * - `true`: The instance is connected. (Connected)
	 */
	export async function status(): Promise<boolean | null | undefined> {
		const state = await State();
		if (state?.pid === undefined) return undefined;
		if (!state.started) return null;

		const status = await SSH.status(state.pid);
		if (status === null)
			Log.quit(
				Block.lined(
					[
						`The instance is not listening for SSH.`,
						`Check ${white(Static.path('Base.Log'))} to debug.`,
					],
					{ bold: true },
				),
				red,
			);
		return status;
	}

	/**
	 * - `undefined`: The instance is starting.
	 * - `null`: The instance could not start.
	 * - `true`: The instance has started.
	 * - `false`: The instance is running.
	 */
	export async function start(): Promise<boolean | null | undefined> {
		const status = await VM.status();
		if (status === null) return undefined;
		if (status === false) return false;

		// MARK: - Check Dependencies

		await Util.ensure(Static.Command.qemuSystem);
		await Util.ensure(Static.Command.qemuImg);
		await Util.ensure(Static.Command.curl);
		await Util.ensure(Static.Command.netcat, `netcat`);
		await Util.ensure(Static.Command.xorriso);

		// MARK: - Download Alpine Image

		const imagePath = Static.path('Base.Images.Remote');
		const imageExists = await exists(imagePath, { isFile: true });
		if (!imageExists) {
			Log.debug(`Downloading ${Static.OS.Image}...`);
			await ensureDir(dirname(imagePath));
			await $`${Static.Command.curl} --progress-bar --location --output ${imagePath} ${Static.OS.Url}`;
		}

		// MARK: - Create Local Disk

		const diskPath = Static.path('Base.Images.Local');
		const diskExists = await exists(diskPath, { isFile: true });
		if (!diskExists) {
			Log.debug(`Creating VM disk...`);
			await copy(Static.path('Base.Images.Remote'), diskPath);
			const result =
				await $`${Static.Command.qemuImg} resize ${diskPath} ${Static.System.DiskSize}`.text();
			if (result.trim() !== 'Image resized.') Log.warn(result);
		}

		// MARK: - Create Cloud-Init ISO

		await ensureDir(Static.path('Base.CloudInit'));

		const metaDataPath = Static.path('Base.CloudInit.MetaData');
		try {
			using metaData = await Deno.open(metaDataPath, {
				createNew: true,
				write: true,
			});
			await writeAll(
				metaData,
				Util.toBinary(Static.CloudInit.MetaData()),
			);
		} catch (error) {
			if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
		}

		const userDataPath = Static.path('Base.CloudInit.UserData');
		try {
			using userData = await Deno.open(userDataPath, {
				createNew: true,
				write: true,
			});

			const PUBLIC_SSH_KEY = await $.request(
				`https://github.com/navtoj.keys`,
			).text();
			if (!PUBLIC_SSH_KEY) Log.quit('Public SSH key not found.');

			const userDataBytes = Util.toBinary(
				Static.CloudInit.UserData({ PUBLIC_SSH_KEY }),
			);
			await writeAll(userData, userDataBytes);
		} catch (error) {
			if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
		}

		const isoPath = Static.path('Base.CloudInit.Iso');
		const isoExists = await exists(isoPath, { isFile: true });
		if (!isoExists) Log.debug(`Creating Cloud-Init ISO...`);

		await $`${Static.Command.xorriso} -as mkisofs -joliet -volid cidata -output ${isoPath} -rock ${metaDataPath} ${userDataPath}`.quiet();

		// MARK: - UEFI Firmware Device

		const bios = `/opt/homebrew/share/qemu/edk2-aarch64-code.fd`;
		const biosExists = await exists(bios, {
			isFile: true,
			isReadable: true,
		});
		if (!biosExists)
			Log.quit(
				Block.lined([
					`File for ${white('-bios')} not found.`,
					white(bios),
				]),
			);

		// MARK: - Start Instance
		const progress = $.progress('Starting...');

		start: try {
			using stateFile = await Deno.open(Static.path('Base.State'), {
				createNew: true,
				write: true,
			});

			try {
				await Deno.copyFile(
					Static.path('Base.Log'),
					Static.path('Base.LogArchive'),
				);
			} catch (error) {
				if (!(error instanceof Deno.errors.NotFound)) throw error;
			}
			await Deno.writeTextFile(Static.path('Base.Log'), '');

			const diskPath = Static.path('Base.Images.Local');
			const params = [
				['-cpu', 'host'],
				['-accel', 'hvf'],
				['-machine', 'virt'],
				['-bios', bios],
				['-m', `${Static.System.Memory}`],
				['-smp', `${Static.System.CPUs}`],
				[
					'-drive',
					`if=none,file=${diskPath},format=${extname(diskPath).slice(1)},id=hd0`,
				],
				['-device', 'virtio-blk-pci,drive=hd0'],
				[
					'-drive',
					`if=none,file=${Static.path('Base.CloudInit.Iso')},format=raw,id=cd0`,
				],
				['-device', 'virtio-blk-pci,drive=cd0'],
				[
					'-nic',
					`user,model=virtio-net-pci,hostfwd=tcp::${SSH.Port}-:22`,
				],
				['-object', 'rng-random,filename=/dev/urandom,id=rng0'],
				['-device', 'virtio-rng-pci,rng=rng0'],
				'-nographic',
				['-serial', `file:${Static.path('Base.Log')}`],
				[
					'-monitor',
					`tcp:127.0.0.1:${Static.System.Port},server,nowait`,
				],
			].flat();
			const qemu = new AbortController();
			const command = new Deno.Command(Static.Command.qemuSystem, {
				args: params,
				stdin: 'null',
				stdout: 'null',
				detached: true,
				signal: qemu.signal,
			}).spawn();

			const state: Type.State = {
				pid: command.pid,
				started: null,
			};
			await writeAll(stateFile, State.toBinary(state));

			const result = await Promise.race([
				command.status.then(status => status.success),
				WatchLog(line =>
					line.trim().endsWith(`${Static.System.Name} login:`),
				),
			]);
			command.unref();

			if (!result) {
				qemu.abort();
				await command.status;
				break start;
			}

			const configPath = Static.path('Base.ConfigSSH');
			const fileExists = await exists(configPath, { isFile: true });
			if (!fileExists) {
				const config = $.dedent`
				Host ${Static.path('Base')}
					HostName localhost
					User ${Static.System.User}
					Port ${SSH.Port}
					StrictHostKeyChecking no
					UserKnownHostsFile /dev/null
					ForwardAgent yes
			`;
				await ensureDir(dirname(configPath));
				await Deno.writeTextFile(configPath, config);
			}
			await SSH.enable();

			state.started = Temporal.Now.zonedDateTimeISO().toLocaleString(
				undefined,
				{
					dateStyle: 'medium',
					timeStyle: 'medium',
				},
			);
			await Deno.writeFile(
				Static.path('Base.State'),
				State.toBinary(state),
			);
			return true;
		} catch (error) {
			if (!(error instanceof Deno.errors.AlreadyExists)) throw error;
		} finally {
			progress.finish();
		}

		return null;
	}

	/**
	 * - `null`: No instance found.
	 * - `false`: The instance is starting.
	 * - `true`: The instance was stopped.
	 */
	export async function stop(): Promise<boolean | null> {
		const status = await VM.status();
		if (status === undefined) return null;
		if (status === null) return false;

		const progress = $.progress('Stopping...');

		try {
			const stop = await $`nc localhost ${Static.System.Port}`
				.stdinText('system_powerdown\n')
				.quiet()
				.code();
			if (stop !== 0) Log.quit(`Failed to start shutdown.`);
			const result = await WatchLog(line =>
				line.trim().endsWith('reboot: Power down'),
			);
			if (!result) Log.quit(`Failed to stop instance.`);
			await SSH.disable();
		} finally {
			progress.finish();
		}

		return true;
	}

	/**
	 * - `false`: The instance is running.
	 * - `null`: No environment to reset.
	 * - `true`: The environment was reset.
	 */
	export async function reset(): Promise<boolean | null>;
	/**
	 * - `false`: The instance is running.
	 * - `null`: No environment to reset.
	 * - `true`: The environment can reset.
	 */
	export async function reset(
		options: RequireAtLeastOne<{ dryRun: boolean }>,
	): Promise<boolean | null>;
	export async function reset(
		options?: RequireAtLeastOne<{ dryRun: boolean }>,
	): Promise<boolean | null> {
		const status = await VM.status();
		if (status !== undefined) return false;

		const dirExists = await exists(Static.path('Base'), {
			isDirectory: true,
			isReadable: true,
		});
		if (!dirExists) return null;
		if (options?.dryRun) return true;

		await Deno.remove(Static.path('Base'), { recursive: true });
		return true;
	}
}

// MARK: - Main

const os = await $`uname -s`.text();
if (os.trim() !== 'Darwin') Log.quit(`Only macOS is supported.`);

const arch = await $`uname -m`.text();
if (arch.trim() !== 'arm64') Log.quit(`Only Apple silicon is supported.`);

const instances = await VM.unknown();
if (instances.length)
	Log.quit(
		Block.lined([
			`Found ${instances.length} unknown ${instances.length > 1 ? 'instances' : 'instance'}.`,
			`Run ${white(`kill ${instances.join(' ')}`)} to clean up.`,
		]),
	);

const args = parseArgs(Deno.args, {
	string: ['install'],
	boolean: ['uninstall'],
});
const stale =
	Deno.env.get('DEVELOPMENT') !== 'true' &&
	import.meta.url !== (await Zshrc.scriptUrl(args.install));
if (args.install || stale) {
	const enabled = await Zshrc.enable();
	const message = Block.lined([
		bold(
			`Script alias ${enabled ? 'added to' : 'updated in'} ${white(join(`~`, Zshrc.ConfigPath))} file.`,
		),
		`Run ${white(Static.path('Base'))} in a new terminal.`,
	]);
	Log.exit(message);
} else if (args.uninstall) {
	if ((await VM.status()) !== undefined)
		Log.quit(
			Block.lined([
				bold('The instance is running.'),
				`Run ${white(`${Static.path('Base')} stop`)} to close.`,
			]),
		);

	await Zshrc.disable();
	const message = Block.lined([
		bold(
			`Alias ${white(Static.path('Base'))} removed from ${white(join(`~`, Zshrc.ConfigPath))} file.`,
		),
		`Close the terminal to uninstall.`,
	]);
	Log.exit(message);
}

Deno.stdin.setRaw(true);
Util.stdout(Ansi.HIDE_CURSOR);
Deno.addSignalListener('SIGINT', () => Log.debug('SIGINT'));
Deno.addSignalListener('SIGTERM', () => Log.debug('SIGTERM'));

switch (args._.length === 1 ? args._[0] : null) {
	case 'start': {
		const { duration, result: start } = await Util.time(() => VM.start());
		Log.debug(format(duration, { ignoreZero: true }));

		if (start == null)
			Log.quit(
				Block.lined([
					bold(
						start === null
							? 'The instance could not start.'
							: 'The instance is starting.',
					),
					`Check ${white(Static.path('Base.Log'))} to debug.`,
				]),
				start === null ? red : yellow,
			);

		const message = Block.lined([
			bold(`The instance ${start ? 'has started' : 'is running'}.`),
			`Run ${white(`ssh ${Static.path('Base')}`)} to connect.`,
		]);
		Log.info(message, start ? green : yellow);
		break;
	}

	case 'stop': {
		const { duration, result: stop } = await Util.time(() => VM.stop());
		Log.debug(format(duration, { ignoreZero: true }));

		if (stop === false)
			Log.quit(
				Block.lined([
					bold('The instance is starting.'),
					`Check ${white(Static.path('Base.Log'))} to debug.`,
				]),
			);

		const message = Block.lined([
			bold(stop ? `The instance has stopped.` : `No instance found.`),
			`Run ${white(`${Static.path('Base')} start`)} to set up.`,
		]);
		Log.info(message, stop ? green : yellow);
		break;
	}

	case 'reset': {
		let reset = await VM.reset({ dryRun: true });

		if (reset === false)
			Log.quit(
				Block.lined([
					bold('The instance is running.'),
					`Run ${white(`${Static.path('Base')} stop`)} to close.`,
				]),
			);

		if (reset) {
			const ask = [
				Block.boxed(bold(`Erase instance and clear data?`), {
					bold: true,
				}),
				Block.lined(`Press ${white(bold('Enter'))} to continue.`),
			].join('\n');
			const confirm = prompt(brightRed(ask));

			Util.stdout(Ansi.moveCursorUpStart(3));
			if (confirm !== '') {
				Util.stdout(
					brightRed(
						Block.lined(
							confirm === null
								? `User input not received.`
								: `Aborted. No changes to environment. `,
						),
					),
					Ansi.ERASE_LINE_AFTER_CURSOR,
					'\n',
				);
				break;
			}
			reset = await VM.reset();
		}

		const message = [
			bold(
				reset ? 'The environment was reset.' : 'No environment found.',
			),
			`Run ${white(`${Static.path('Base')} start`)} to set up.`,
		];
		Log.info(Block.lined(message, { bold: true }), reset ? green : yellow);
		break;
	}

	case 'help': {
		const message = [
			Block.boxed(
				[
					bold('Contact Support'),
					`\x1b]8;;https://github.com/navtoj/scripts/issues\x1b\\https://github.com/navtoj/scripts/issues\x1b]8;;\x1b\\`,
				],
				{ bold: true },
			),
			Block.lined([
				bold('List Ports'),
				white(`lsof +c0 -anP -i TCP -c ${Static.Command.qemuSystem}`),
			]),
			Block.lined([
				bold('List Processes'),
				white(
					`ps -ww -eo pid,command | grep ${Static.Command.qemuSystem} | grep -v grep`,
				),
			]),
		].join('\n');
		Log.info(message);
		break;
	}

	default: {
		const status = await VM.status();
		const indicator =
			status === undefined
				? brightRed('Offline')
				: status === null
					? brightYellow('Loading')
					: status
						? brightGreen('Connected')
						: brightBlue('Online');
		const message = [
			Block.boxed(['QEMU Alpine', Static.OS.Version, bold(indicator)]),
			Block.lined([
				`Usage: ${Static.path('Base')} <command>`,
				'Commands: start | stop | reset | help',
			]),
		];
		if (status === false)
			message.push(
				green(
					Block.lined(
						`Run ${white(`ssh ${Static.path('Base')}`)} to connect.`,
					),
				),
			);
		Log.info(message.join('\n'));
		break;
	}
}
