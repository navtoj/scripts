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
exec deno run --ext=ts --no-lock --allow-all "$SCRIPT_URL" "$FLAGS"
*/
// deno-lint-ignore-file no-import-prefix no-namespace
import { border, type Border } from 'jsr:@cliffy/table@1.0.0';
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
	dim,
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
import type {
	GetPathValue,
	Path as Paths,
} from 'npm:@clickbar/dot-diver@^2.0.0';
import type { RequireAtLeastOne } from 'npm:type-fest@^5.4.4';

namespace Static {
	export namespace OS {
		const enum Semantic {
			Major = '3',
			Minor = '21',
			Patch = '0',
		} // 3.23.3
		const Firmware = 'uefi'; // bios
		export const Arch = 'aarch64'; // x86_64
		export const Version = `${Semantic.Major}.${Semantic.Minor}.${Semantic.Patch}`;
		export const Image = `nocloud_alpine-${Version}-${Arch}-${Firmware}-cloudinit-r0.qcow2`;
		export const Url = `https://dl-cdn.alpinelinux.org/alpine/${`v${Semantic.Major}.${Semantic.Minor}` || 'latest-stable'}/releases/cloud/${Image}`;
	}

	export namespace System {
		export const Name = 'qemu';
		export const User = 'alpine';
		export const CPUs = 4;
		export const Memory = '6G';
		export const DiskSize = '8G';
		export const Port = 4444;
		export const ID = `${Name}.${User}`;
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
		export async function UserData() {
			const response = await $.request(
				`https://github.com/navtoj.keys`,
			).text();
			const PUBLIC_SSH_KEY = response.trim();
			if (!PUBLIC_SSH_KEY) Log.quit('Public SSH key not found.');

			const GitUser = await $`git config --global user.name`
				.noThrow()
				.quiet()
				.text();
			if (!GitUser) Log.quit(`Git ${white('user.name')} is not set.`);
			const GitEmail = await $`git config --global user.email`
				.noThrow()
				.quiet()
				.text();
			if (!GitEmail) Log.quit(`Git ${white('user.email')} is not set.`);

			const tool = [
				// System
				{ package: 'doas' },
				{ package: 'bash' },
				{ package: 'nano' },
				{ package: 'grep' },
				{ package: 'coreutils' },
				{ package: 'moreutils', binary: 'sponge' },
				// Connection
				{ package: 'openssh', binary: ['ssh', 'sshd'] },
				{ package: 'tmux' },
				// Development
				{ package: 'netcat-openbsd', binary: 'nc' },
				{ package: 'curl' },
				{ package: 'wget' },
				{ package: 'git' },
				{ package: 'jq' },
				{ package: 'git-filter-repo' },
				// Programming
				{ package: 'sqlite', binary: 'sqlite3' },
				{ package: 'py3-uv', binary: 'uv' },
				{ binary: ['bun', 'bunx'] },
				// Virtualization
				{ package: 'docker' },
				{ package: 'docker-compose' },
				{ package: 'containerd' },
				{ package: 'kubectl' },
				// https://pkgs.alpinelinux.org/packages?repo=main&arch=aarch64&branch=v3.21
			];

			const json = {
				resize_rootfs: true,
				growpart: {
					mode: 'auto',
					devices: ['/'],
				},
				manage_etc_hosts: true,
				hostname: `${System.Name}`,
				users: [
					{
						name: `${System.User}`,
						groups: ['wheel', 'docker'],
						shell: '/bin/bash',
						doas: [`permit nopass ${System.User}`],
						lock_passwd: false,
						ssh_authorized_keys: [PUBLIC_SSH_KEY],
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
						ClientAliveCountMax 3`,
					},
					{
						path: '/etc/motd',
						permissions: '0644',
						content: Block.boxed(
							`Run ${green(System.ID)} to verify environment.`,
						),
					},
					{
						path: '/etc/default/grub',
						permissions: '0644',
						append: true,
						content: $.dedent`
						GRUB_TIMEOUT=0
						GRUB_TIMEOUT_STYLE=hidden`,
					},
					{
						path: `/home/${System.User}/.bash_profile`,
						permissions: '0644',
						owner: `${System.User}:${System.User}`,
						append: true,
						content: $.dedent`
						# https://docs.warp.dev/terminal/warpify/subshells#automatically-warpify-subshells
						printf '\\eP$f{ "hook": "SourcedRcFileForWarp", "value": { "shell": "bash", "uname": "'$(uname)'", "tmux": ${tool.findIndex(t => t.package === 'tmux') !== -1} }}\\x9c'
						# docs.astral.sh/uv
						eval "$(uv generate-shell-completion bash)"
						eval "$(uvx --generate-shell-completion bash)"
						# user tools
						export PATH="$HOME/.local/bin:$PATH"`,
					},
					{
						path: `/home/${System.User}/.local/bin/${System.ID}`,
						permissions: '0755',
						owner: `${System.User}:${System.User}`,
						content: $.dedent`
						#!/bin/bash
						set -euo pipefail
						echo "${Block.boxed(bold('System Information'), { bold: true })}"
						cat << EOF
						${Block.lined([bold('Kernel'), `$(uname -r)`])}
						${Block.lined([bold('Memory'), `$(free -h 2>/dev/null | grep Mem | awk '{ print $2, "=", $7, "+", $3 }')`])}
						${Block.lined([bold('Disk'), `$(df -h / 2>/dev/null | tail -1 | awk '{ print $2, "=", $4, "+", $3 }')`])}
						EOF
						echo "${Block.boxed(bold('Installed Tools'), { bold: true })}"
						DEPENDENCIES=(
							${tool
								.flatMap(t => t.binary ?? t.package)
								.map(t => `"${t}"`)
								.join('\n\t')}
						)
						for cmd in "\${DEPENDENCIES[@]}"; do
							if command -v "$cmd" &>/dev/null; then
								echo "  $cmd"
							else
								echo "${red(`${border.left} $cmd not found`)}"
							fi
						done`,
					},
					{
						path: `/home/${System.User}/.local/bin/setup.sh`,
						permissions: '0755',
						owner: `${System.User}:${System.User}`,
						content: $.dedent`
						#!/bin/bash
						set -euo pipefail
						chsh --shell /bin/bash
						# git
						git config --global init.defaultBranch main
						git config --global push.autoSetupRemote true
						git config --global pull.rebase true
						git config --global user.name "${GitUser}"
						git config --global user.email "${GitEmail}"
						git config --global user.signingkey "${PUBLIC_SSH_KEY}"
						git config --global commit.gpgsign true
						git config --global gpg.format ssh
						# cleanup script
						rm "$0"`,
					},
				],
				packages: tool.flatMap(t => t.package ?? []),
				runcmd: [
					'apk update && apk upgrade',
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
					// user setup
					`su -l ${System.User} -c '~/.local/bin/setup.sh;'`,
					`su -l ${System.User} -c 'curl -fsSL https://bun.com/install | bash'`,
				],
				final_message: Block.lined(`The instance is ready!`),
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
		qemuSystem = `qemu-system-${Static.OS.Arch}`,
		qemuImg = 'qemu-img',
		curl = 'curl',
		netcat = 'nc',
		xorriso = 'xorriso',
	}

	const Location = {
		_: homedir() as `~`,
		Zshrc: '.zshrc',
		SSH: {
			_: `.ssh`,
			Config: `config`,
		},
		Base: {
			_: `.${System.ID}`,
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

	/**
	 * - `of`: Use `null` to get the root path.
	 * - `options.pretty`: Uses `~` instead of `/home/<user>` for better readability.
	 */
	export function path<P extends path.Key | null>(
		of: P,
		options?: { pretty: boolean },
	): path.Value<P> {
		if (of === null) return Location._ as path.Value<P>;
		const parts = of.split('.');
		const route: string[] = [options?.pretty ? '~' : Location._];
		let node: unknown = Location;
		for (const part of parts) {
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
		type Location = typeof Location;
		type Path = Paths<Location>;
		export type Key = Exclude<Path, `${string}._` | '_'>;

		type Split<Text extends string> =
			Text extends `${infer Head}.${infer Tail}`
				? [Head, ...Split<Tail>]
				: [Text];

		type Accumulate<
			Parts extends string[],
			Prefix extends string = '',
		> = Parts extends [
			infer Head extends string,
			...infer Tail extends string[],
		]
			? Prefix extends ''
				? [Head, ...Accumulate<Tail, Head>]
				: [
						`${Prefix}.${Head}`,
						...Accumulate<Tail, `${Prefix}.${Head}`>,
					]
			: [];

		type _Get<P extends Path> = GetPathValue<Location, P>;
		type Get<P extends Path> = `${P}._` extends Path
			? _Get<`${P}._`>
			: _Get<P>;

		type Map<T extends string[]> = T extends [
			infer Head extends Key,
			...infer Tail extends string[],
		]
			? [Get<Head>, ...Map<Tail>]
			: [];

		type Join<
			T extends string[],
			Separator extends string = '/',
		> = T extends [
			infer Head extends string,
			...infer Tail extends string[],
		]
			? Tail extends []
				? `${Head}`
				: `${Head}${Separator}${Join<Tail>}`
			: '';

		export type Value<K extends Key | null> = K extends string
			? `${Get<'_'>}/${Join<Map<Accumulate<Split<K>>>>}`
			: Get<'_'>;
		type _ = Value<path.Key | null>;
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

	const PositiveInteger = z.coerce.number().int().positive();
	export type PositiveInteger<T extends number> = T extends 0
		? never
		: `${T}` extends `${infer _}.${infer _}`
			? never
			: `${T}` extends `-${infer _}`
				? never
				: T;

	export const NonNegative = z.coerce.number().int().nonnegative();

	export const State = z.object({
		pid: PositiveInteger,
		started: z.string().nonempty().nullable(),
	});
	export type State = z.infer<typeof State>;

	/** A safe port number for development use. */
	export const Port = z.coerce.number().int().gte(3000).lte(8080);
	export type Port = z.infer<typeof Port>;
}

/**
 * https://www.compart.com/en/unicode/block/U+2500
 */
namespace Block {
	const LightUp = '╵' as const;
	const LightDown = '╷' as const;
	const HeavyUp = '╹' as const;
	const HeavyDown = '╻' as const;

	export const Bold = {
		top: '━',
		topMid: '┳',
		topLeft: '┏',
		topRight: '┓',
		bottom: '━',
		bottomMid: '┻',
		bottomLeft: '┗',
		bottomRight: '┛',
		left: '┃',
		leftMid: '┣',
		mid: '━',
		midMid: '╋',
		right: '┃',
		rightMid: '┫',
		middle: '┃',
	} as const satisfies Border;

	export function lined(
		input: string | (string | string[])[],
		options?: RequireAtLeastOne<{
			bold: boolean;
			padding: boolean;
		}>,
	) {
		options = { bold: false, padding: true, ...options };
		if (!Array.isArray(input)) input = [input];
		const vertical = !options.bold ? border.middle : Bold.middle;
		const lines = [
			input
				.map(line =>
					Array.isArray(line)
						? line
								.map(l =>
									l
										.split('\n')
										.map(ln => `${vertical} ${ln}`)
										.join('\n'),
								)
								.join('\n')
						: line
								.split('\n')
								.map(l => `${vertical} ${l}`)
								.join('\n'),
				)
				.join(`\n${vertical}\n`),
		];
		if (options.padding) {
			lines.unshift(options.bold ? HeavyDown : LightDown);
			lines.push(options.bold ? HeavyUp : LightUp);
		}
		return lines.join('\n');
	}

	export function boxed(
		input: string | string[],
		options: {
			bold: boolean;
		} = { bold: false },
	) {
		if (!Array.isArray(input)) input = [input];
		const chars = !options.bold ? border : Bold;

		let top = '';
		let middle = '';
		let bottom = '';

		for (const [index, line] of input.entries()) {
			const width = unicodeWidth(stripAnsiCodes(line)) + 2;
			const border = chars['mid'].repeat(width);
			top += border;
			middle += ` ${line} `;
			bottom += border;
			if (index + 1 === input.length) continue;
			top += chars['topMid'];
			middle += chars['middle'];
			bottom += chars['bottomMid'];
		}

		return [
			`${chars['topLeft']}${top}${chars['topRight']}`,
			`${chars['middle']}${middle}${chars['middle']}`,
			`${chars['bottomLeft']}${bottom}${chars['bottomRight']}`,
		].join('\n');
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

	export namespace TUI {
		export function setup() {
			Deno.stdin.setRaw(true);
			Util.stdout(Ansi.HIDE_CURSOR);
		}
		export function cleanup() {
			Util.stdout(Ansi.SHOW_CURSOR);
			Deno.stdin.setRaw(false);
		}
	}

	export async function ask(options: {
		title: string;
		subtitle: string;
		rejection: string;
	}) {
		if (
			options.title.includes('\n') ||
			options.subtitle.includes('\n') ||
			options.rejection.includes('\n')
		)
			throw new Error('Input strings cannot contain newlines.');

		const ask = brightRed(
			[
				Block.boxed(bold(options.title), {
					bold: true,
				}),
				Block.lined(options.subtitle),
			].join('\n'),
		);

		let confirm: string | null;
		if (Util.DEBUG) {
			Log.info(ask);
			await new Promise(r => setTimeout(r, 500));
			confirm = '';
		} else confirm = prompt(ask);

		Util.stdout(Ansi.moveCursorUpStart(3));
		if (confirm !== '') {
			Util.stdout(
				brightRed(
					Block.lined(
						confirm === null
							? `User input not received.`
							: options.rejection,
					),
				),
				Ansi.ERASE_LINE_AFTER_CURSOR,
				'\n',
			);
			return false;
		}
		return true;
	}

	export const DEV = Deno.env.get('DEV') === 'true';
	export const DEBUG = Deno.env.get('DEBUG') === 'true';
}

namespace Log {
	type Message = string | string[];
	type Format = (str: string) => string;
	function parse(message: Message) {
		return Array.isArray(message) ? message.join('\n') : message;
	}

	export function info(message: Message, fmt: Format = blue) {
		console.info(fmt(parse(message)));
	}
	export function warn(message: Message, fmt: Format = yellow) {
		console.warn(fmt(parse(message)));
	}
	export function error(message: Message, fmt: Format = red) {
		console.error(fmt(parse(message)));
	}
	export function debug(message: Message, fmt: Format = bgBrightGreen) {
		if (Util.DEBUG) console.debug(fmt(parse(message)));
	}

	/**
	 * Exit the script with return code `0`.
	 * - `message`: The text to display.
	 */
	export function exit(message: Message, fmt?: Format): never {
		info(message, fmt);
		Util.TUI.cleanup();
		Deno.exit();
	}
	/**
	 * Exit the script with return code `1`.
	 * - `message`: The error text to display.
	 */
	export function quit(message: Message, fmt?: Format): never {
		error(message, fmt);
		Util.TUI.cleanup();
		Deno.exit(1);
	}
}

namespace File {
	/** @returns The file content, or `null` if the file does not exist. */
	async function file(options: { path: string }): Promise<string | null>;
	/** If the file does not exist, it will be created. */
	async function file(options: {
		path: string;
		value: string;
	}): Promise<void>;
	async function file(options: {
		path: string;
		value?: string;
	}): Promise<string | null | void> {
		if (options?.value === undefined) {
			try {
				return await Deno.readTextFile(options.path);
			} catch (error) {
				if (!(error instanceof Deno.errors.NotFound)) throw error;
				return null;
			}
		}
		await ensureDir(dirname(options.path));
		await Deno.writeTextFile(options.path, options.value);
	}

	/**
	 * Remove lines matching a condition from the content.
	 * - `string[]`: No matching lines found; no change made.
	 * - `string`: At least one matching line removed; the new content.
	 */
	function _remove(options: {
		content: string;
		match: (line: string) => boolean;
	}) {
		const lines = options.content.split('\n');
		const filtered = lines.filter(l => !options.match(l.trim()));
		if (filtered.length === lines.length) return filtered;
		return filtered.join('\n');
	}

	/**
	 * Prepend a line to a file if it doesn't already exist.
	 * - `false`: The line already exists; no change made.
	 * - `null`: Line added to an empty or new file.
	 * - `true`: Line added to the top of the file.
	 */
	export async function prepend(options: { path: string; line: string }) {
		const content = await file({ path: options.path });
		if (content?.startsWith(options.line)) return false;
		const cleaned = _remove({
			content: content ?? '',
			match: line => line === options.line,
		});
		const lines = Array.isArray(cleaned) ? cleaned : cleaned.split('\n');
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
		const removed = _remove({ content, match });
		if (Array.isArray(removed)) return false;
		await file({ path, value: removed });
		return true;
	}
}

namespace Zshrc {
	namespace prefix {
		export const scriptUrl =
			'https://raw.githubusercontent.com/navtoj/scripts/' as const;
		export const configLine =
			`alias ${Static.System.ID}='deno run --ext=ts --no-lock --allow-all "` as const;
	}
	namespace suffix {
		export const scriptUrl = `/mac/${Static.System.ID}.ts` as const;
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
				`https://api.github.com/repos/navtoj/scripts/commits?per_page=1&sha=main&path=mac/${Static.System.ID}.ts`,
			).json();
			hash = z
				.string()
				.regex(/^[a-f0-9]{40}$/i, { error: 'Invalid script hash.' })
				.parse(json[0].sha, { reportInput: true });
		}
		ScriptUrl = `${prefix.scriptUrl}${hash}${suffix.scriptUrl}`;
		return ScriptUrl;
	}
	async function ConfigLine(): Promise<string> {
		return `${prefix.configLine}${await scriptUrl()}${suffix.configLine}`;
	}

	const ConfigPath = Static.path('Zshrc');
	export async function enable() {
		const configLine = await ConfigLine();
		const removed = await File.remove({
			path: ConfigPath,
			match: line =>
				line !== configLine && zod.configLine.safeParse(line).success,
		});
		const added = await File.prepend({
			path: ConfigPath,
			line: configLine,
		});
		return (added ?? true) ? (removed ? null : true) : false;
	}
	export async function disable() {
		const configLine = await ConfigLine();
		return await File.remove({
			path: ConfigPath,
			match: line => line === configLine,
		});
	}
}

namespace SSH {
	export const Port = 2222 as const;
	const ConfigPath = Static.path('SSH.Config');
	const ConfigLine =
		`Include ${Static.path('Base.ConfigSSH', { pretty: true })}` as const;

	export async function enable() {
		return await File.prepend({
			path: ConfigPath,
			line: ConfigLine,
		});
	}
	export async function disable() {
		return await File.remove({
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

namespace VM {
	/** `timeout`: The maximum time (s) to wait for a match before giving up. */
	async function WatchLog<T extends number>(
		match: (line: string) => boolean,
		options: { timeout: Type.PositiveInteger<T>; signal?: AbortSignal },
	): Promise<boolean> {
		const tail = new AbortController();
		const command = new Deno.Command('tail', {
			args: ['-f', '-n', '0', Static.path('Base.Log')],
			stdout: 'piped',
			stderr: 'null',
			stdin: 'null',
			signal: AbortSignal.any(
				[
					tail.signal,
					options.signal ?? [],
					AbortSignal.timeout(options.timeout * 1000),
				].flat(),
			),
		}).spawn();

		try {
			let buffer = '';
			const decoder = new TextDecoder();
			for await (const chunk of command.stdout) {
				buffer += decoder.decode(chunk, { stream: true });
				const lines = buffer.split('\n');
				if (lines.some(match)) return true;
				buffer = lines.pop() ?? '';
			}
		} finally {
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
			const state = Type.State.parse(json, { reportInput: true });
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
			const parsed = Type.State.parse(state, { reportInput: true });
			return Util.toBinary(JSON.stringify(parsed, null, 2));
		}
	}

	/**
	 * Find instances running the local image.
	 */
	export async function instances(
		options?: RequireAtLeastOne<{
			unknown: boolean;
		}>,
	): Promise<number[]> {
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
			const pid = Type.State.shape.pid.parse(i, { reportInput: true });
			if (options?.unknown && state?.pid === pid) return [];
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
						`Check ${white(Static.path('Base.Log', { pretty: true }))} to debug.`,
					],
					{ bold: true },
				),
				red,
			);
		return status;
	}

	/**
	 * - `true`: The instance has started.
	 * - `false`: Failed to start instance.
	 */
	export async function start(): Promise<boolean> {
		// MARK: - Check Dependencies

		await Util.ensure(Static.Command.qemuSystem);
		await Util.ensure(Static.Command.qemuImg);
		await Util.ensure(Static.Command.curl);
		await Util.ensure(Static.Command.netcat, `netcat`);
		await Util.ensure(Static.Command.xorriso);

		// MARK: - Download Alpine Image

		const imagePath = Static.path('Base.Images.Remote');
		const imageExists = await exists(imagePath, { isFile: true });
		image: if (!imageExists) {
			Log.debug(`Downloading ${Static.OS.Image}...`);
			await ensureDir(dirname(imagePath));
			if (Util.DEV)
				try {
					await Deno.rename(imagePath, join(`/tmp`, Static.OS.Image));
					break image;
				} catch (error) {
					if (!(error instanceof Deno.errors.NotFound)) throw error;
				}
			const download =
				await $`${Static.Command.curl} --progress-bar --location --fail --silent --output ${imagePath} ${Static.OS.Url}`.code();
			if (download !== 0)
				Log.quit(
					Block.lined(
						[
							bold(`Failed to download image.`),
							white(Static.OS.Image),
							Static.OS.Url.replace(Static.OS.Image, ''),
						],
						{ bold: true },
					),
				);
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

			const userDataBytes = Util.toBinary(
				await Static.CloudInit.UserData(),
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
				stderr: 'inherit',
				detached: true,
				signal: qemu.signal,
			}).spawn();

			const state: Type.State = {
				pid: command.pid,
				started: null,
			};
			await writeAll(stateFile, State.toBinary(state));

			const tail = new AbortController();
			const found = await Promise.race([
				command.status.then(() => false),
				WatchLog(
					l => l.trim().endsWith(`${Static.System.Name} login:`),
					{ timeout: 60, signal: tail.signal },
				),
			]);

			tail.abort();
			if (!found) {
				qemu.abort();
				await command.status;
				break start;
			} else command.unref();

			const configPath = Static.path('Base.ConfigSSH');
			const fileExists = await exists(configPath, { isFile: true });
			if (!fileExists) {
				const config = $.dedent`
				Host ${Static.System.ID}
					HostName 127.0.0.1
					User ${Static.System.User}
					Port ${SSH.Port}
					StrictHostKeyChecking no
					UserKnownHostsFile /dev/null
					LogLevel ERROR`;
				// ForwardAgent yes
				await ensureDir(dirname(configPath));
				await Deno.writeTextFile(configPath, config);
			}
			await SSH.enable();

			state.started = new Date().toLocaleString(undefined, {
				dateStyle: 'medium',
				timeStyle: 'medium',
			});
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
		return false;
	}

	/**
	 * - `true`: The instance has stopped.
	 * - `null`: Failed to start shutdown.
	 * - `false`: Failed to stop instance.
	 */
	export async function stop(): Promise<boolean | null> {
		const progress = $.progress('Stopping...');
		try {
			const stop = await $`nc localhost ${Static.System.Port}`
				.stdinText('system_powerdown\n')
				.quiet()
				.code();
			if (stop !== 0) return null;
			const result = await WatchLog(
				line => line.trim().endsWith('reboot: Power down'),
				{ timeout: 30 },
			);
			if (!result) return false;
			await SSH.disable();
		} finally {
			progress.finish();
		}
		return true;
	}

	/**
	 * - `false`: No environment to reset.
	 * - `true`: The environment was reset.
	 */
	export async function reset(): Promise<boolean>;
	/**
	 * - `false`: No environment to reset.
	 * - `true`: The environment can reset.
	 */
	export async function reset(options: { dryRun: boolean }): Promise<boolean>;
	export async function reset(
		options?: RequireAtLeastOne<{ dryRun: boolean }>,
	): Promise<boolean> {
		const dirExists = await exists(Static.path('Base'), {
			isDirectory: true,
			isReadable: true,
		});
		if (!dirExists) return false;
		if (options?.dryRun) return true;

		if (Util.DEV)
			try {
				await Deno.rename(
					Static.path('Base.Images.Remote'),
					join(`/tmp`, Static.OS.Image),
				);
			} catch (error) {
				if (!(error instanceof Deno.errors.NotFound)) throw error;
			}
		await Deno.remove(Static.path('Base'), { recursive: true });
		return true;
	}

	/** Tunnel a local port to the instance. */
	export namespace Port {
		namespace Tunnel {
			const address = `127.0.0.1`;
			export const prefix = `ssh -f -o ExitOnForwardFailure=yes -N -L ${address}:`;
			export const middle = `:${address}:`;
			export const suffix = ` qemu.alpine`;
			export function command<T extends Type.Port | `([0-9]+)`>(port: T) {
				return `${Tunnel.prefix}${port}${Tunnel.middle}${port}${Tunnel.suffix}` as const;
			}
			export type command = ReturnType<typeof command>;
		}

		async function exists(tunnel: Tunnel.command) {
			const code = await $.raw`${exists.command(tunnel)}`.quiet().code();
			return code === 0;
		}
		namespace exists {
			export const prefix = `ps -ww -eo pid,command | grep -E '`;
			export const suffix = `' | grep -v grep`;
			export function command<T extends Tunnel.command>(port: T) {
				return `${prefix}${port}${suffix}` as const;
			}
		}

		export async function list() {
			const command = Tunnel.command('([0-9]+)');
			const output = await $.raw`${exists.command(command)}`
				.noThrow()
				.lines();
			const lines = output.filter(Boolean);
			if (!lines.length) return [];

			const _regex = `^([0-9]+) (?:/usr/bin/)?${command}$` as const;
			const regex = new RegExp(_regex);

			return lines.flatMap(line => {
				const match = line.trim().match(regex);
				if (!match) return [];

				const [, pid, local, remote] = match;
				return {
					pid: Type.State.shape.pid.parse(pid, { reportInput: true }),
					local: Type.Port.parse(local, { reportInput: true }),
					remote: Type.Port.parse(remote, { reportInput: true }),
				};
			});
		}

		/**
		 * - `true`: The tunnel has opened.
		 * - `null`: The tunnel already exists.
		 * - `false`: Failed to open the tunnel.
		 */
		export async function open(port: Type.Port) {
			const tunnel = Tunnel.command(port);
			const found = await exists(tunnel);
			if (found) return null;
			const code = await $.raw`${tunnel}`.quiet().code();
			return code === 0;
		}

		/**
		 * - `true`: The tunnel has closed.
		 * - `null`: The tunnel does not exist.
		 * - `false`: Failed to close the tunnel.
		 */
		export async function close(port: Type.Port) {
			const tunnel = Tunnel.command(port);
			const found = await exists(tunnel);
			if (!found) return null;
			const code = await $`pkill -f ${tunnel}`.code();
			return code === 0;
		}
	}
}

// MARK: - Checks -

Deno.addSignalListener('SIGINT', () => Log.debug('SIGINT'));
Deno.addSignalListener('SIGTERM', () => Log.debug('SIGTERM'));

const os = await $`uname -s`.text();
if (os.trim() !== 'Darwin') Log.quit(`Only macOS is supported.`);

const arch = await $`uname -m`.text();
if (arch.trim() !== 'arm64') Log.quit(`Only Apple silicon is supported.`);

const instances = await VM.instances({ unknown: true });
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
	!Util.DEV && import.meta.url !== (await Zshrc.scriptUrl(args.install));

if (args.install || stale) {
	const enabled = await Zshrc.enable();
	const message = Block.lined([
		bold(
			`Script alias ${enabled ? 'added to' : 'updated in'} ${white(Static.path('Zshrc', { pretty: true }))} file.`,
		),
		`Run ${white(Static.System.ID)} in a new terminal.`,
	]);
	Log.exit(message);
} else if (args.uninstall) {
	if ((await VM.status()) !== undefined)
		Log.quit(
			Block.lined([
				bold('The instance is running.'),
				`Run ${white(`${Static.System.ID} stop`)} to close.`,
			]),
		);

	await Zshrc.disable();
	const message = Block.lined([
		bold(
			`Alias ${white(Static.System.ID)} removed from ${white(Static.path('Zshrc', { pretty: true }))} file.`,
		),
		`Close the terminal to uninstall.`,
	]);
	Log.exit(message);
}

// MARK: - Main -

Util.TUI.setup();

switch (
	args._.length === 1 ||
	(args._.length >= 2 && args._.length <= 3 && args._[0] === 'port')
		? args._[0]
		: null
) {
	case 'start': {
		const status = await VM.status();
		const Action = {
			Connect: `Run ${white(`ssh ${Static.System.ID}`)} to connect.`,
			Debug: `Check ${white(Static.path('Base.Log', { pretty: true }))} to debug.`,
		};

		if (status !== undefined)
			Log.exit(
				Block.lined([
					bold(
						`The instance is ${status === null ? 'starting' : 'running'}.`,
					),
					status === false ? Action.Connect : Action.Debug,
				]),
				yellow,
			);

		const { duration, result: start } = await Util.time(() => VM.start());
		Log.debug(format(duration, { ignoreZero: true }));

		const message = Block.lined([
			bold(`The instance ${start ? 'has started' : 'could not start'}.`),
			start ? Action.Connect : Action.Debug,
		]);

		if (start) Log.info(message, green);
		else Log.quit(message);
		break;
	}

	// TODO: Rename `port` command to `tunnel` and use `--[no-]port=<local>[:<remote>]` to support multiple and different local/remote port combinations.
	case 'port': {
		const input = Deno.args.at(1) ?? null;
		if (input === null)
			Log.exit(
				[
					Block.lined([
						'Usage',
						white(`${Static.System.ID} port <command>`),
					]),
					Block.lined([
						'Commands',
						`${white(`list`)} / ${white(`<port>`)}`,
					]),
					Block.lined(
						`Prefix ${white(`<port>`)} with ${white(`minus (-)`)} to close.`,
						{ padding: false },
					),
				].join('\n'),
			);

		const status = await VM.status();
		const Action = {
			Start: `Run ${white(`${Static.System.ID} start`)} to set up.`,
			Debug: `Check ${white(Static.path('Base.Log', { pretty: true }))} to debug.`,
		};
		if (status == null) {
			const message = Block.lined([
				bold(
					`The instance ${status === null ? 'is starting' : 'was not found'}.`,
				),
				status === null ? Action.Debug : Action.Start,
			]);

			if (status === null) Log.quit(message);
			else Log.exit(message, yellow);
		}

		if (input === 'list') {
			const { duration, result: tunnels } = await Util.time(() =>
				VM.Port.list(),
			);
			Log.debug(format(duration, { ignoreZero: true }));

			if (!tunnels.length)
				Log.exit(
					Block.lined(
						[
							bold('No active tunnels found.'),
							`Run ${white(`${Static.System.ID} port <port>`)} to open.`,
						],
						{
							bold: true,
						},
					),
					yellow,
				);

			const list = tunnels
				.sort((a, b) => a.local - b.local)
				.map(p => `${p.local} ──⏵ ${p.remote} ${dim(`(${p.pid})`)}`);
			Log.exit(Block.lined(list));
		}

		const negative = input.startsWith('-');
		const port = Type.Port.parse(negative ? input.slice(1) : input, {
			reportInput: true,
		});

		const { duration, result } = await Util.time(async () => {
			if (negative) return await VM.Port.close(port);
			return await VM.Port.open(port);
		});
		Log.debug(format(duration, { ignoreZero: true }));

		if (result) Deno.exit();
		const message = Block.lined([
			result === null
				? `Tunnel ${negative ? 'does not exist' : 'is already open'}.`
				: `Failed to ${negative ? 'close' : 'open'} tunnel.`,
		]);

		if (result === false) Log.quit(message);
		else Log.info(message, yellow);
		break;
	}

	case 'stop': {
		const status = await VM.status();
		const Action = {
			Start: `Run ${white(`${Static.System.ID} start`)} to set up.`,
			Debug: `Check ${white(Static.path('Base.Log', { pretty: true }))} to debug.`,
		};

		if (status == null) {
			const message = Block.lined([
				bold(
					`The instance ${status === null ? 'is starting' : 'was not found'}.`,
				),
				status === null ? Action.Debug : Action.Start,
			]);

			if (status === null) Log.quit(message);
			else Log.exit(message, yellow);
		}

		// ssh qemu.alpine "ps -o args | grep 'tmux' | grep '\-CC' | grep -v 'grep' | wc -l"
		if (status) {
			const confirm = await Util.ask({
				title: 'Disconnect active instance sessions?',
				subtitle: `Press ${white(bold('Enter'))} to continue.`,
				rejection: 'Aborted. No changes to environment.',
			});
			if (!confirm) break;
			await $`ssh ${Static.System.ID} "fuser /dev/pts/* 2>/dev/null | xargs kill -HUP"`
				.noThrow()
				.quiet();
		}

		const { duration, result: stop } = await Util.time(() => VM.stop());
		Log.debug(format(duration, { ignoreZero: true }));

		const message = Block.lined([
			bold(`The instance ${stop ? 'has stopped' : 'could not stop'}.`),
			stop ? Action.Start : Action.Debug,
		]);

		if (stop) Log.info(message, green);
		else Log.quit(message);
		break;
	}

	case 'reset': {
		const status = await VM.status();
		if (status !== undefined)
			Log.quit(
				Block.lined([
					bold('The instance is running.'),
					`Run ${white(`${Static.System.ID} stop`)} to close.`,
				]),
			);

		let reset = await VM.reset({ dryRun: true });

		if (reset) {
			const confirm = await Util.ask({
				title: 'Erase instance and clear data?',
				subtitle: `Press ${white(bold('Enter'))} to continue.`,
				rejection: 'Aborted. No changes to environment.',
			});
			if (!confirm) break;
			reset = await VM.reset();
		}

		const message = [
			bold(
				reset ? 'The environment was reset.' : 'No environment found.',
			),
			`Run ${white(`${Static.System.ID} start`)} to set up.`,
		];
		Log.info(Block.lined(message, { bold: true }), reset ? green : yellow);
		break;
	}

	case 'help': {
		Log.info([
			Block.boxed(
				[
					'Contact Support',
					`\x1b]8;;https://github.com/navtoj/scripts/issues\x1b\\https://github.com/navtoj/scripts/issues\x1b]8;;\x1b\\`,
				],
				{ bold: !true },
			),
			Block.lined([
				'Watch Log',
				white(`tail -F ${Static.path('Base.Log', { pretty: true })}`),
			]),
			Block.lined([
				'List Connections',
				white(`lsof +c0 -anP -i TCP -c ${Static.Command.qemuSystem}`),
			]),
			Block.lined([
				'List Processes',
				white(
					`ps -ww -eo pid,command | grep ${Static.System.ID} | grep -v grep`,
				),
			]),
		]);
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
			Block.lined(['Usage', white(`${Static.System.ID} <command>`)]),
			Block.lined([
				'Commands',
				`${white('start')} / ${white('port')} / ${white('stop')} / ${white('reset')} / ${white('help')}`,
			]),
		];
		if (status === false)
			message.push(
				green(
					Block.lined(
						`Run ${white(`ssh ${Static.System.ID}`)} to connect.`,
					),
				),
			);
		Log.info(message);
		break;
	}
}

Util.TUI.cleanup();
