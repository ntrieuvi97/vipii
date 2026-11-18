# vipii: phát hiện và ẩn danh dữ liệu cá nhân tiếng Việt

Công cụ tương tự Microsoft Presidio nhưng làm riêng cho dữ liệu Việt Nam.
**Không phụ thuộc thư viện ngoài, chạy hoàn toàn offline**: dữ liệu không rời khỏi máy.

Mục đích chính là che PII trong tài liệu nội bộ **trước khi** gửi cho LLM cloud,
sau đó khôi phục lại giá trị thật trong câu trả lời của LLM.

```
Tài liệu nội bộ → vipii che → LLM cloud → vipii khôi phục → người dùng
```

## Cài đặt

Yêu cầu Python 3.10 trở lên. Không cần thư viện nào khác. Lệnh dưới đây luôn lấy **bản mới nhất**
trên nhánh `main` (không ghim phiên bản).

Linux (Debian, Ubuntu, Linux Mint…) và macOS (Homebrew) chặn `pip install` vào Python hệ thống
(lỗi `externally-managed-environment`, PEP 668). Đừng dùng `--break-system-packages`; chọn một trong hai cách:

**Cách 1: dùng lệnh `vipii` (khuyên dùng), cài bằng pipx**

```bash
sudo apt install pipx && pipx ensurepath      # Debian/Ubuntu/Mint; macOS: brew install pipx
pipx install git+https://github.com/ntrieuvi97/vipii
```

Mở lại terminal rồi chạy `vipii --help`. Cập nhật lên bản mới nhất:

```bash
pipx install --force git+https://github.com/ntrieuvi97/vipii
```

**Cách 2: dùng như thư viện Python trong dự án của bạn, cài vào venv**

```bash
python3 -m venv .venv
.venv/bin/pip install git+https://github.com/ntrieuvi97/vipii
# cập nhật:
.venv/bin/pip install --upgrade --force-reinstall --no-deps git+https://github.com/ntrieuvi97/vipii
```

Windows và môi trường đã có venv đang bật: `pip install git+https://github.com/ntrieuvi97/vipii`.
Muốn cố định một bản (ví dụ cho CI): thêm `@v0.1.0` vào cuối URL.

## Loại dữ liệu hỗ trợ

| Loại | Cách nhận dạng |
|---|---|
| `PERSON` | Họ phổ biến (có dấu và không dấu), từ xưng hô (anh/chị/ông/bà…), ngữ cảnh; loại trừ địa danh, tên đường đặt theo danh nhân, cụm từ hành chính viết hoa |
| `PHONE_NUMBER` | Di động 03/05/07/08/09, cố định 02x, +84, (028), (+84); chấp nhận dấu cách, chấm, gạch |
| `NATIONAL_ID` | CCCD 12 số, viết liền hoặc tách nhóm 3 (kiểm tra mã tỉnh và mã thế kỷ/giới tính), CMND 9 số (cần ngữ cảnh) |
| `TAX_CODE` | MST 10 số, mã chi nhánh `-xxx`; checksum đúng được **cộng điểm**, nhưng vẫn cần ngữ cảnh ("MST", "mã số thuế") |
| `CREDIT_CARD` | Đầu số Napas 9704, Visa, Master, JCB, Amex, UnionPay, có **kiểm tra Luhn** |
| `BANK_ACCOUNT` | 6–19 số, cần ngữ cảnh (STK, tên khoảng 30 ngân hàng Việt Nam) |
| `ADDRESS` | Chuỗi số nhà, ngõ/hẻm, đường, phường/xã, quận/huyện, tỉnh/TP; hiểu viết tắt P., Q., TP. |
| `LICENSE_PLATE` | Biển số ô tô (30A-123.45) và xe máy (29-B1 123.45) |
| `DATE_OF_BIRTH`, `PASSPORT`, `SOCIAL_INSURANCE`, `EMAIL` | Mẫu kết hợp ngữ cảnh |
| *Tự định nghĩa* | Từ khóa bí mật kinh doanh: tên dự án, khách hàng, mã sản phẩm… |

## Dùng trong Python

```python
from vipii import Analyzer, anonymize, deanonymize

text = "Anh Nguyễn Văn An, SĐT 0912345678, MST 0300588569"
res = anonymize(text)
res.text     # 'Anh <PERSON_1>, SĐT <PHONE_NUMBER_1>, MST <TAX_CODE_1>'
res.mapping  # {'<PERSON_1>': 'Nguyễn Văn An', ...}  ← DỮ LIỆU NHẠY CẢM, giữ trong nội bộ

reply = call_llm(res.text)                  # LLM chỉ thấy placeholder
print(deanonymize(reply, res.mapping))      # khôi phục; chấp nhận cả [PERSON_1], < person_1 >

# Hội thoại nhiều lượt: truyền mapping để placeholder giữ nguyên qua các lượt
res2 = anonymize("Nguyễn Văn An gọi lại", mapping=res.mapping)   # vẫn là <PERSON_1>

# Toán tử theo loại: replace (mặc định) | mask | redact | hash
anonymize(text, operators={"PHONE_NUMBER": "mask"})              # ******5678
# mask: mã số dài (SĐT, CCCD, STK, thẻ…) giữ 4 số cuối; loại khác che toàn bộ chữ và số.
# hash: HMAC-SHA256, cần salt bí mật (biến môi trường VIPII_SALT), nếu thiếu sẽ cảnh báo.

# Bí mật kinh doanh
a = Analyzer(custom_terms={"PROJECT": ["Phượng Hoàng", "Falcon"], "CLIENT": ["Vingroup"]})
anonymize("Dự án Falcon cho Vingroup", analyzer=a).text          # 'Dự án <PROJECT_1> cho <CLIENT_1>'
```

## Dùng qua CLI

```bash
pip install -e .           # hoặc: python -m vipii ...
vipii analyze hop_dong.txt                                   # JSON các thực thể
vipii anonymize hop_dong.txt --map map.json \
      --op BANK_ACCOUNT=mask --terms PROJECT=secrets.txt > an_toan.txt
vipii deanonymize tra_loi_llm.txt --map map.json             # khôi phục
```

File `map.json` được ghi với quyền `0600` (chỉ chủ sở hữu đọc được). Nếu file đã tồn tại,
mapping cũ được dùng tiếp để placeholder nhất quán giữa các tài liệu.

## Skill / plugin cho AI agent

Repo này đồng thời là **plugin** cho Claude Code và Antigravity. Plugin chỉ cài *skill*
(hướng dẫn agent che dữ liệu **trước khi** gửi ra ngoài, giữ file mapping an toàn, khôi phục
câu trả lời). Bản thân thư viện vẫn cần cài riêng bằng `pip install` ở trên.

### Claude Code

```text
/plugin marketplace add ntrieuvi97/vipii
/plugin install vipii@vipii
```

Hoặc từ shell:

```bash
claude plugin marketplace add ntrieuvi97/vipii
claude plugin install vipii@vipii
```

Skill xuất hiện dưới tên `/vipii:vipii`. Cập nhật bằng `claude plugin marketplace update vipii`.

### Antigravity (App, CLI, IDE)

```bash
agy plugin install https://github.com/ntrieuvi97/vipii
```

Trong CLI tương tác: `/plugin install https://github.com/ntrieuvi97/vipii`. Ngoài ra có thể
copy repo vào `~/.gemini/config/plugins/vipii/` (toàn cục) hoặc `.agents/plugins/vipii/`
(chỉ một dự án). Skill gọi bằng `/vipii`.

### Agent khác (Codex, Hermes…) hoặc chỉ cần skill

Copy [`skills/vipii/`](skills/vipii/SKILL.md) vào thư mục skills của agent, ví dụ
`~/.claude/skills/vipii/`, `~/.hermes/skills/vipii/` hoặc `~/.gemini/config/skills/vipii/`.

## Guard: ép agent chỉ đọc nội dung đã che (Claude Code)

Skill chỉ *nhờ* agent che dữ liệu; agent vẫn có thể quên và đọc file thô. `vipii guard` *ép* ở tầng
công cụ bằng hook của Claude Code:

| Hook | Việc làm |
|---|---|
| `PostToolUse` | Che mọi chuỗi trong kết quả của `Read`, `Bash`, `WebFetch`, MCP… **trước khi** model thấy |
| `PreToolUse` | Đổi placeholder trong input của `Edit`/`Write`/`Bash` về giá trị thật (để agent sửa được file đã che); chặn đọc file mapping, ảnh, PDF |
| `UserPromptSubmit` | Chặn prompt chứa PII và hiện bản đã che để bạn gửi lại |
| `MessageDisplay` | Khôi phục giá trị thật trong chữ **bạn đọc**; model vẫn chỉ thấy placeholder |

```bash
vipii guard --install              # ghi hook vào ~/.claude/settings.json (giữ nguyên cấu hình khác)
vipii guard --install --project    # hoặc chỉ cho dự án hiện tại (./.claude/settings.json)
vipii guard --uninstall            # gỡ
vipii guard --purge                # xóa mọi file mapping đã lưu
```

Cần `pipx install` hoặc venv như ở trên: đường dẫn Python tuyệt đối được ghi vào hook. Nếu bạn chuyển/xóa
môi trường đó, chạy lại `--install`. Mapping lưu ở `~/.vipii/guard/<session>.json` (quyền 0600, tự xóa sau 7 ngày),
agent không đọc được. Biến môi trường: `VIPII_GUARD=off` (tắt hết), `VIPII_GUARD_PROMPT=off` (không chặn prompt),
`VIPII_GUARD_TERMS="NHAN=file1.txt;DUAN=file2.txt"` (từ khóa bí mật), `VIPII_GUARD_DIR`. Cố ý gửi nguyên văn: thêm
`#allow-pii` vào prompt.

Đã chạy thử với Claude Code thật: model chỉ thấy `<PHONE_NUMBER_1>`; transcript trên đĩa không chứa giá trị thật;
`Edit` qua placeholder ghi đúng giá trị thật vào file; prompt có PII bị chặn; hook hỏng thì công cụ bị chặn.

**Giới hạn, cần đọc trước khi tin vào guard:**

- **Chỉ chặn được văn bản bình thường.** Nếu agent (hoặc một prompt injection) tự chạy `rev file`, `base64 file`
  hay script biến đổi dữ liệu, PII đã bị biến dạng sẽ lọt qua; đã thử và xác nhận. Guard chống rò rỉ *vô tình*,
  không chống agent cố tình lách. Muốn đảm bảo cứng, agent không được có quyền truy cập file thô (che trước bằng
  `vipii anonymize`, rồi chỉ cho agent thấy thư mục đã che).
- Chỉ che được những gì bộ nhận dạng thấy: tên lạ, địa chỉ viết thường… vẫn lọt như mọi nơi khác trong vipii.
- Ảnh, PDF, âm thanh không che được nên `Read` bị từ chối; hãy chuyển sang văn bản và che trước.
- Prompt bạn gõ bị **chặn rồi gửi lại**, không được tự động che (hook không sửa được prompt). Muốn tự động che
  cả prompt thì cần proxy giữa agent và LLM, chưa có trong bản này.
- Mapping theo phiên: gửi lại bản đã che trong *cùng* phiên thì placeholder được khôi phục; sang phiên mới thì không.
- Hook chạy sau công cụ nên không rút lại được output: nhờ `PreToolUse` dùng cùng lệnh làm "chốt chặn" mà guard
  hỏng thì công cụ bị chặn từ đầu, nhưng hook `PostToolUse` bị timeout riêng lẻ vẫn có thể để lọt. Telemetry
  OpenTelemetry của Claude Code ghi output gốc trước khi hook chạy (chỉ ở máy bạn).
- Antigravity và các agent khác chưa được hỗ trợ; chưa chạy thử guard trên Windows (unit test có chạy trong CI).

## Cơ chế chấm điểm

Mỗi bộ nhận dạng gán điểm 0–1, mặc định chỉ giữ thực thể có điểm ≥ 0.5 (`threshold`).
- **Mẫu + kiểm tra** (checksum, Luhn, mã tỉnh CCCD) cho điểm nền.
- **Từ ngữ cảnh** gần đó ("MST", "STK", "sinh ngày", "trú tại"…) cộng thêm điểm.
  Cửa sổ ngữ cảnh dừng ở con số gần nhất, để từ khóa của số này không bị tính cho số bên cạnh.
- Các dãy số chung chung (CMND 9 số, STK, BHXH, hộ chiếu) **bắt buộc có ngữ cảnh**.
- Khi các thực thể chồng lấn nhau, giữ thực thể điểm cao nhất, sau đó ưu tiên span dài nhất.
- Từ khóa "phủ định" chỉ tính ở phía trước giá trị: số dạng điện thoại đứng sau "MST", "STK" hay "CCCD"
  thì bị trừ điểm.
- Khoảng trắng Unicode (NBSP khi copy từ Word hoặc web) được xử lý như dấu cách, còn văn bản trả về giữ nguyên.

## An toàn

- **Văn bản đầu vào chứa chuỗi giống placeholder** (`<PHONE_NUMBER_1>`, `[PERSON_1]`) được che thành
  `<VIPII_LITERAL_n>` và khôi phục nguyên văn. Nhờ vậy tài liệu không đáng tin cũng không thể khiến
  `deanonymize` thay vào giá trị thật của bản ghi khác.
- `deanonymize` chỉ thay placeholder có trong mapping, và chỉ thay một lượt. Placeholder lạ do LLM bịa ra
  được giữ nguyên.
- Regex được thiết kế để tránh backtracking thảm họa (ReDoS); test suite có các đầu vào độc hại.
  Thời gian xử lý tăng tuyến tính: khoảng 1 MB/s với văn bản thường, tệ nhất đo được khoảng 4 giây/MB
  với văn bản dày đặc số điện thoại.
- Khi không chắc, vipii chọn che (fail-closed): ngữ cảnh phủ định chỉ phân xử giữa hai loại
  chứ không làm mất giá trị; tên đứng trước chức danh viết hoa vẫn được che, kể cả khi bị che lẹm sang chức danh.
- Khoảng trắng Unicode và ký tự vô hình (mọi ký tự định dạng Unicode `Cf` như zero-width, soft hyphen, LRM/RLM,
  BOM, cùng ký tự lấp chỗ Hangul) được xử lý như dấu cách khi nhận dạng, nên chèn chúng vào số hoặc tên
  không làm thoát khỏi nhận dạng trong các trường hợp đã kiểm thử.

## Hạn chế (cần biết trước khi đưa vào sản xuất)

1. **Tên người dựa trên luật, chưa có model NER.** Sẽ bỏ sót tên không có họ phổ biến
   và không có từ xưng hô (ví dụ chữ ký một từ "Duc"), và có thể nhận nhầm cụm từ
   viết hoa bắt đầu bằng họ (đã chặn một danh sách cụm phổ biến). Có thể cắm thêm NER qua `Analyzer.add()`.
2. **Chưa có bộ dữ liệu đánh giá độc lập.** Bộ test (kèm fuzz test) và văn bản mẫu đều do nhóm phát triển viết,
   nên chưa phản ánh được độ chính xác thật. Cần đo trên dữ liệu thật của doanh nghiệp trước khi tin dùng.
   Địa chỉ viết thường hoàn toàn (`12 nguyễn huệ, q1`) và cùng một tên viết khác hoa/thường hiện chưa được xử lý.
   Tên 5–6 chữ (`Tôn Nữ Thị Minh Châu`) được che, nhưng chuỗi tên + chức danh viết hoa có thể bị che lẹm sang cả chức danh.
   Khi một tên người nằm trong địa chỉ có điểm cao hơn, địa chỉ có thể chỉ được che một phần.
3. Không nhận ra bí mật kinh doanh dạng tự do (giá chào thầu, chiến lược…), chỉ nhận
   các từ khóa đã khai báo.
4. Offset của thực thể tính trên văn bản đã chuẩn hóa NFC.
5. Đây là **một lớp** bảo vệ, không thay thế hợp đồng DPA/ZDR, phân quyền và nhật ký kiểm toán.

## Phát triển

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
```

Góp ý và báo lỗi (đặc biệt là các trường hợp nhận sai hoặc bỏ sót, kèm câu ví dụ)
xin gửi tại [Issues](https://github.com/ntrieuvi97/vipii/issues).
**Đừng đính kèm dữ liệu cá nhân thật.**

## Giấy phép

MIT. Xem file [LICENSE](LICENSE).
