# php-ebpf-tracer

PHP の DTrace/USDT プローブを eBPF から拾って、リクエスト単位の分散トレースを
OTLP で送信する自動計装エージェントです。PHP 側にはエクステントションもコード変更も
不要で、必要なのは `--enable-dtrace` 付きでビルドされた PHP だけです。

```
  php (--enable-dtrace)                 kernel                    php-ebpf-tracer (Go)
 ┌──────────────────────┐   uprobe   ┌──────────────┐  ringbuf  ┌────────────────────┐
 │ php:request__startup │───────────▶│              │           │ event.Decode       │
 │ php:function__entry  │───────────▶│ php_tracer   │──────────▶│ pipeline.Aggregator│
 │ php:function__return │───────────▶│ .bpf.o       │  16 MiB   │  (閾値判定)         │
 │ php:request__shutdown│───────────▶│ shadow stack │           │ otelexport         │
 └──────────────────────┘            └──────────────┘           └─────────┬──────────┘
                                                                          │ OTLP
                                                                          ▼
                                                              Collector / Jaeger / …
```

## できること

- **自動計装**: `request__startup` / `request__shutdown` / `function__entry` /
  `function__return` の 4 プローブに libbpf の USDT サポートでアタッチします。
- **カーネル内でスパン化**: プロセス (tgid,tid) ごとのシャドウスタックで
  entry/return を突き合わせ、**完成したスパンだけ**を ring buffer に流します。
  entry/return をそのまま転送する場合に比べてレコード数が半分になります。
- **テールサンプリング**: `request__shutdown - request__startup` の差分が
  `-min-duration` 以上のリクエストだけを OTLP で送信します。遅いリクエストの
  スパンはすべて残り、速いリクエストは 1 バイトも送信されません。
- **MySQL クエリ** (`-trace-mysql`): mysqlnd に uprobe を張り、mysqli / PDO の
  クエリを、それを発行した PHP 関数の子スパンとして送ります。
- **ID はカーネルで採番**: trace id / span id を BPF 側で生成し、Go 側は
  そのまま OTel スパンに載せます。

## 動作要件

| 項目 | 要件 |
| --- | --- |
| OS | Linux (macOS では後述の Docker 経由で動かします) |
| カーネル | 5.8 以上 (BPF ring buffer)。BTF は不要です |
| 権限 | root もしくは `CAP_BPF` + `CAP_PERFMON`。コンテナなら `--privileged` |
| PHP | `./configure --enable-dtrace` でビルドされたもの |
| 環境変数 | PHP プロセス側に **`USE_ZEND_DTRACE=1`** (関数プローブに必須) |

### PHP 側で必要な 2 つの準備

**1. `--enable-dtrace` 付きビルド**

ディストリビューション配布の PHP は基本的に `--enable-dtrace` が無効なので、
`docker/php.Dockerfile` でソースからビルドしています。手元の PHP に
プローブがあるかは次のコマンドで確認できます。

```sh
readelf -n "$(which php)" | grep -c 'Provider: php'   # 0 なら未対応
```

**2. `USE_ZEND_DTRACE=1`**

`php:function__entry` / `php:function__return` は、PHP が起動時に
`zend_execute_ex` を dtrace 版に差し替えたときだけ発火します。その差し替えは
起動時の環境変数 `USE_ZEND_DTRACE=1` でのみ有効になります
(php-src `Zend/zend.c`)。

```sh
USE_ZEND_DTRACE=1 php-fpm     # あるいは systemd unit / Dockerfile の ENV で
```

`request__startup` / `request__shutdown` はこの変数なしでも発火するので、
`-trace-functions=false` でリクエストスパンだけ取る運用なら不要です。
なお、この変数を有効にすると (トレースしていないときも) 全関数呼び出しが
ラッパー経由になるため、PHP 側に一定のオーバーヘッドが乗ります。

## クイックスタート (Docker Compose)

PHP (dtrace 有効) + トレーサ + 負荷生成 + Jaeger が一式立ち上がります。

```sh
docker compose up --build     # PHP のビルドに数分かかります
open http://localhost:16686   # Service: php-demo
```

デモアプリのエンドポイントは `/fast` (数百 µs)、`/slow` (約 250 ms)、
`/random` (0-400 ms)、`/error` (例外)。デフォルトの閾値は 100 ms なので、
Jaeger には `/slow` と遅い `/random` だけが現れます。

PHP バイナリは named volume 経由で共有し、PHP プロセスもトレーサも
**同じ inode** を参照するようにしています。uprobe は inode に対して張られるため、
コンテナごとに overlayfs のコピーを持つと probe が当たりません。

## 手動ビルド (Linux)

```sh
# 必要: clang, llvm, libbpf >= 1.5 (ヘッダ + ライブラリ), libelf, zlib, Go 1.24+
make                                    # build/php_tracer.bpf.o と build/php-ebpf-tracer
sudo ./build/php-ebpf-tracer \
    -bpf-object build/php_tracer.bpf.o \
    -binary "$(which php)" \
    -service-name my-php-app \
    -min-duration 100ms \
    -otlp-endpoint localhost:4317
```

システムに libbpf を入れずにビルドする場合は、git submodule の libbpf (v1.8-dev, 2bbc483)
をビルドして静的リンクする `LIBBPF_BUNDLED=1` を指定します。

```sh
# 必要: clang, llvm, libelf, zlib, Go 1.24+ (libbpf は不要)
git submodule update --init             # 未取得なら make が自動で実行します
make LIBBPF_BUNDLED=1                   # build/libbpf に libbpf.a を作ってから全体をビルド
```

Collector を立てずに中身を確認したいときは `-otlp-protocol stdout` を使います。

```sh
sudo ./build/php-ebpf-tracer -binary "$(which php)" -min-duration 0 -otlp-protocol stdout
```

## 認証付きで送る (Grafana Tempo / Grafana Cloud)

Basic 認証のパスワード (トークン) は `ps` に出ないよう環境変数でだけ渡します。
Grafana Cloud の場合、ユーザーはスタックの Instance ID、パスワードは
`traces:write` スコープを持つ Access Policy トークンです。

```sh
export PHP_TRACER_OTLP_BASIC_AUTH_USER=123456
export PHP_TRACER_OTLP_BASIC_AUTH_PASSWORD=glc_xxxxxxxx

# OTLP/HTTP (Grafana Cloud の OTLP gateway)。パスは /v1/traces まで書く
sudo -E ./build/php-ebpf-tracer -binary "$(which php)" \
    -otlp-protocol http \
    -otlp-endpoint https://otlp-gateway-prod-ap-northeast-0.grafana.net/otlp/v1/traces

# OTLP/gRPC (Tempo へ直接)。host:port のときは -otlp-insecure=false で TLS を有効に
sudo -E ./build/php-ebpf-tracer -binary "$(which php)" \
    -otlp-protocol grpc \
    -otlp-endpoint tempo-prod-10-prod-ap-northeast-0.grafana.net:443 \
    -otlp-insecure=false
```

Basic 認証以外 (Bearer トークン、マルチテナントの `X-Scope-OrgID` など) は
`-otlp-header` で渡せます。こちらも `ps` に出したくなければ
`OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20xxx` のように環境変数で
渡してください (`-otlp-header` / Basic 認証を指定すると環境変数のヘッダは
上書きされます)。

## 主なオプション

| フラグ | 既定値 | 説明 |
| --- | --- | --- |
| `-binary` | `/usr/local/bin/php` | USDT ノートを持つ実行ファイル。複数指定可 (`php` と `php-fpm` など) |
| `-pid` | `-1` | 特定プロセスだけを対象にする。`-1` で全プロセス |
| `-attach-mode` | `auto` | `global` (pid=-1 で一括) / `scan` (`/proc` を走査して個別アタッチ) / `auto` (global を試して失敗したら scan) |
| `-scan-interval` | `3s` | scan モードで新しい PHP プロセスを探す間隔 |
| `-min-duration` | `100ms` | **送信判定の閾値**。`request__shutdown - request__startup` がこれ以上のものだけ送る。`0` で全送信 |
| `-min-span` | `0` | これより短い関数スパンをバッファに積む前に捨てる (子は生存する祖先に付け替え)。捨てたスパンは `-max-spans` に数えない |
| `-max-depth` | `32` (`-include-path` 指定時は `128`) | この深さより深い呼び出しはスパンにしない。深さは `-include-path` の対象外の呼び出しも含めて数える。カーネルが追跡できるのは 128 までで、それより大きくしても効果はない |
| `-bpf-min-func` | `0` | カーネル側で短い関数スパンを捨てる。安価だが子スパンが root 直下に付け替わる |
| `-include-path` | (なし = 全ファイル) | このディレクトリ以下のファイルで定義された関数だけをスパンにする。カーネル側で前方一致判定。複数指定可 (最大 8 件) |
| `-max-spans` | `5000` | 1 リクエストあたりのスパン数上限 |
| `-export-queue-size` | `4 × -max-spans` (最低 2048) | OTLP エクスポータが送信待ちで抱えられるスパン数。溢れた分は SDK が捨てる |
| `-trace-functions` | `true` | `false` にすると関数プローブを張らず、リクエストスパンだけにする |
| `-trace-mysql` | `false` | mysqlnd 経由の MySQL クエリをスパンにする ([MySQL クエリ](#mysql-クエリ)) |
| `-mysqlnd` | (自動検出) | mysqlnd.so のパス。mysqlnd が PHP に静的リンクされているならその実行ファイル |
| `-mysql-raw-query` | `false` | SQL をそのまま送る。既定では文字列・数値リテラルを `?` に置き換える |
| `-otlp-protocol` | `grpc` | `grpc` / `http` / `stdout` |
| `-otlp-endpoint` | (空) | `host:port` か `https://host/path` 形式の URL。URL なら TLS はスキームで決まり、http ではパスがそのまま使われる。空なら `OTEL_EXPORTER_OTLP_*` 環境変数に従う |
| `-otlp-insecure` | `true` | `host:port` 指定時に TLS を使わない。リモートに送るときは `-otlp-insecure=false` |
| `-otlp-header` | (なし) | 追加ヘッダ `key=value`。複数指定可 |
| `-otlp-basic-auth-user` | (空) | Basic 認証のユーザー (`PHP_TRACER_OTLP_BASIC_AUTH_USER`)。パスワードは環境変数 `PHP_TRACER_OTLP_BASIC_AUTH_PASSWORD` からのみ読む |
| `-service-name` | `php` | `service.name` |
| `-max-request-age` | `1m` | `request__shutdown` が来ないリクエストのバッファを捨てるまでの時間 |

## 対象ファイルの絞り込み

`-include-path` を指定すると、そのディレクトリ以下のファイルで定義された関数だけが
スパンになります。vendor 配下のフレームワークやライブラリを除いて、アプリのコードだけを
見たい場合に使います。

```sh
php-ebpf-tracer \
  -include-path /var/www/app/app \
  -include-path /var/www/app/routes
```

- 判定は関数を定義したファイルのパスに対する前方一致で、**カーネル内で**行います。
  対象外の関数は ring buffer にも Go 側のバッファにも載りません。
- 末尾に `/` がなければ補います。`/var/www/app` が `/var/www/app2/` に一致することは
  ありません。
- 対象外の関数から呼ばれた関数は、スパンになっている最も近い祖先 (なければ root) の
  子になります。フレームワーク経由で呼ばれるコントローラも root 直下などに正しくぶら下がります。
- `-max-depth` と `php.call.depth` は、対象外の関数も含めた実際の呼び出しの深さで数えます。
  フレームワークはアプリのコードを深い位置から呼ぶため (Laravel のコントローラのアクションは
  深さ 40 前後)、`-include-path` を指定したときの `-max-depth` の既定値は、カーネルが追跡できる
  上限の 128 になります。対象外のフレームはスパンにならないので、上限を上げてもスパンはほとんど
  増えません。
- 対象外の関数でも USDT プローブ自体は発火するので、プローブのオーバーヘッドは変わりません。
  減るのは ring buffer に書くレコードと、Go 側の処理量です。
- パスは最大 8 件、長さは 127 バイトまでです。カーネルはパスを 127 バイトまでしか
  読まないため、それより深いパスは判定できません。

## MySQL クエリ

`-trace-mysql` を指定すると、mysqli / PDO (pdo_mysql) が mysqlnd 経由で発行した
クエリを、発行元の PHP 関数の子スパン (span kind `CLIENT`) として送ります。

```sh
sudo ./build/php-ebpf-tracer -binary /usr/sbin/php-fpm8.5 -trace-mysql
```

mysqlnd には USDT がなく、ディストリビューションのパッケージはシンボルも
落としてありますが、メソッドテーブル (`mysqlnd_mysqlnd_conn_data_methods`,
`mysqlnd_mysqlnd_command_methods`) は公開シンボルです。起動時にテーブルの
該当スロットを `R_*_RELATIVE` 再配置から読み、関数のファイルオフセットに
uprobe を張ります。

| 計測区間 | 対象 |
| --- | --- |
| `conn_data::query` の入口〜戻り | `mysqli_query`, `PDO::query` / `exec`, エミュレートされた prepare |
| `command::stmt_execute` の入口〜`query_read_result_set_header` の戻り | ネイティブの prepared statement の実行 |

- どちらも結果ヘッダの受信までで、行の fetch は含みません。
- ネイティブ prepare の SQL は `command::stmt_prepare` で取り、同じ接続で
  初めて見る statement id の execute に結び付けます (サーバが返す id は
  プローブからは見えないため)。prepare 自体はスパンにしません。
- 属性は OTel の DB 規約に従い `db.system.name` (と旧名の `db.system`) =
  `mysql`, `db.query.text`, `db.operation.name` を付けます。スパン名は
  `SELECT` などの操作名です。mysqlnd が失敗を返したクエリはステータスが Error に
  なります。
- SQL はカーネルで先頭 1023 バイトまでコピーし、切れた場合は
  `php.db.query.truncated=true` を付けます。
- クエリスパンは `-min-span` の対象外ですが、`-max-spans` には数えます。
- 対応しているのはメソッドテーブルの並びを確認済みの mysqlnd (PHP 8.5) だけです。
  テーブルのサイズが違う場合は起動時にエラーになります。

## 送信判定 (テールサンプリング) の仕組み

1. `request__startup` でカーネルが trace id / root span id を採番し、
   per-request state を `requests` ハッシュマップに作ります。
2. 関数スパンはリクエストが終わるまで **Go 側のメモリにバッファ**されます
   (`-max-spans` 件まで)。この時点ではまだ何も送信しません。
3. `request__shutdown` で `ts_end - ts_start` を計算し、`-min-duration` 未満なら
   バッファごと破棄します。閾値以上なら木構造を組み立てて OTLP に流します。

閾値未満のリクエストではエクスポータもシリアライズも一切走らないため、
高スループットなアプリでも送信側のコストは遅いリクエストの分だけで済みます。

## アタッチ方式 (global と scan)

PHP バイナリが PIE (`Type: DYN`) の場合、**カーネル 5.15 未満では
pid を指定しない一括アタッチができません** (libbpf が BPF cookie なしでは
プロセスのロードベースを解決できないため)。`-attach-mode auto` が既定で、
まず pid=-1 を試し、拒否されたら `/proc` を走査して 1 プロセスずつ
アタッチする scan モードに自動で切り替わります。

scan モードでは `-scan-interval` ごとに `/proc/<pid>/exe` の inode を
対象バイナリと突き合わせ、増えたプロセスにはアタッチし、消えたプロセスの
link は破棄します。inode で照合しているのでマウント名前空間が違っても
一致します。コンテナから使う場合はホストの `/proc` が見える必要があるため、
`pid: host` (compose) もしくは `--pid=host` を付けてください。

scan モードの弱点はスキャン間隔より短命なプロセスを取りこぼすことです。
php-fpm や `php -S` のような常駐プロセスなら問題になりません。
短命な CLI プロセスを確実に拾いたい場合はカーネル 5.15 以上を使うか、
PHP を non-PIE でビルドしてください。

## 設計メモ

**シャドウスタック** — `function__entry` は `frames[depth]` に開始時刻と span id を
積むだけ、`function__return` がそれを取り出して 1 レコードを ring buffer に書きます。
関数名・クラス名・行番号は return 側のプローブ引数からそのまま読めるので、
entry 側で文字列をコピーするのは、関数名が `main` かどうかと `-include-path` を判定するときだけです。
`-include-path` の指定がなければ、ベリファイアがその判定コードごと取り除きます。
対象外のフレームには祖先の span id を引き継がせておくので、子のスパンは
`frames[depth-1]` を見るだけで正しい親を得られます。

**壊れた木の修復** — `zend_bailout` (fatal error / `exit()`) で巻き戻された場合や
`-min-span` でスパンを落とした場合、子スパンは親を失います。
`pipeline.Request.finalize` が生存している最も近い祖先 (なければ root) に
付け替えるので、木が分断されることはありません。

**送信キュー** — 1 リクエスト分のスパンは OTel SDK の BatchSpanProcessor に一度に渡され、
キューに入りきらない分は SDK が黙って捨てます。キューは `-export-queue-size` で広げてあり、
さらに root スパンを最初に積むので、溢れても失われるのは後ろの関数スパンだけで、
リクエストスパンは残ります。

**時刻** — BPF 側は `bpf_ktime_get_ns()` (CLOCK_MONOTONIC) です。
起動時に一度だけ CLOCK_MONOTONIC と CLOCK_REALTIME の差分を取り、その
オフセットで壁時計に変換します (`internal/monoclock`)。オフセットを取り直さない
ことで、NTP がずれてもトレース間で時刻が飛ばないようにしています。

**CO-RE 不使用** — カーネル構造体を一切参照していないので BTF なしの
カーネル (Docker Desktop の LinuxKit など) でもそのままロードできます。

## 制限事項

- 関数スパンの対象は **PHP のユーザーランド関数のみ**です。`function__entry` は内部関数
  (`usleep` 等) では発火しません。
- `main` (スクリプトのトップレベルのコード) はスパンにしません。エントリスクリプトは
  リクエストスパンが表しており、それ以外はほぼオートローダによるクラスファイルの
  `include` / `require` だからです。その中から呼ばれた関数は、最も近い祖先の子になります。
- `bpf_get_current_pid_tgid()` は初期 PID 名前空間の PID を返します。
  コンテナ内の PID とは一致しません。`-pid` に渡すのもホスト側の PID です。
- SIGKILL されたプロセスのカーネル側 state は `-max-request-age` の
  スイープで回収されます。
- 関数プローブは呼び出しごとに発火するため、深い再帰や大量の関数呼び出しを行う
  アプリでは `-max-depth` / `-bpf-min-func` でイベント量を絞ってください。

## リポジトリ構成

```
bpf/php_tracer.h        BPF と Go で共有するレコードのワイヤフォーマット定義
bpf/php_tracer.bpf.c    USDT プローブ + シャドウスタック + ring buffer
internal/event/         ring buffer レコードのデコード (cgo なし)
internal/bpftracer/     libbpfgo でのロード・アタッチ・ポーリング
internal/pipeline/      リクエスト単位のバッファリングと閾値判定
internal/otelexport/    OTel スパン組み立てと OTLP 送信
internal/mysqlnd/       mysqlnd のメソッドテーブルから uprobe の位置を求める (cgo なし)
internal/monoclock/     CLOCK_MONOTONIC → 壁時計の変換
cmd/php-ebpf-tracer/    CLI
docker/                 PHP (dtrace 有効) とトレーサのイメージ
examples/               デモアプリと負荷生成スクリプト
```

## トラブルシューティング

**関数スパンが 1 つも出ない (`spans_buffered=0`)**
PHP プロセスに `USE_ZEND_DTRACE=1` が渡っていません。リクエストスパンだけが
出ている場合はほぼこれです。

**`attach ... : operation not supported`**
PIE バイナリ + カーネル 5.15 未満です。`-attach-mode scan` が自動で使われますが、
コンテナから使う場合は `--pid=host` が必要です。

**`load BPF object: ... permission denied` + verifier のログ**
カーネルの verifier がプログラムを拒否しています。ログの末尾に理由が出ます。
`-max-depth` を下げても変わらない場合は BPF プログラム側の修正が必要です。

**`spans_dropped_cap` が増える**
1 リクエストの関数呼び出しが `-max-spans` を超えています。`-max-depth` を
下げるか `-max-spans` を上げてください。

**動作確認のワンライナー**

```sh
# トレーサの統計 (30 秒ごと)
docker compose logs -f tracer | grep msg=stats

# Jaeger に届いているか
curl -s 'http://localhost:16686/api/services'
```
