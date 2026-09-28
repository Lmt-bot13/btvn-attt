# Môn học: An toàn thông tin

Họ và tên: Lưu Minh Trí

Lớp: K59.KMT



## 1. Tìm hiểu thuật toán mã hoá hiện đại DES, AES mô tả đc thuật toán, quy trình mã hoá/giải mã cài đặt AES trên 1 ngôn ngữ lập trình nào đó

### 1.1. Tổng quan mã hoá đối xứng

Mã hoá đối xứng dùng **một khoá bí mật duy nhất** cho cả hai chiều mã hoá và giải mã.

```text
Bản rõ (P) ──► [ Mã hoá E(K, P) ] ──► Bản mã (C) ──► [ Giải mã D(K, C) ] ──► Bản rõ (P)
                       ▲                                        ▲
                       └────────────── cùng khoá K ─────────────┘
```

Đặc điểm chính:

- Tốc độ nhanh, phù hợp mã hoá lượng dữ liệu lớn.

- Khó khăn chính là **phân phối khoá**: hai bên phải chia sẻ khoá bí mật qua một kênh an toàn.

- DES và AES đều là **mã khối** (block cipher): dữ liệu được chia thành các khối có độ dài cố định rồi mã hoá từng khối.

### 1.2. Thuật toán DES

**DES (Data Encryption Standard)** được chuẩn hoá năm 1977, dựa trên **mạng Feistel**.

| Thông số | Giá trị |
|---|---|
| Kích thước khối | 64 bit |
| Độ dài khoá | 64 bit (trong đó 8 bit kiểm tra chẵn lẻ, chỉ **56 bit** hiệu dụng) |
| Số vòng | 16 vòng Feistel |
| Khoá con | 16 khoá con, mỗi khoá 48 bit |

#### Quy trình mã hoá DES

**Bước 1.** Khối bản rõ 64 bit đi qua **hoán vị đầu IP** (Initial Permutation).

**Bước 2.** Kết quả được chia đôi thành nửa trái `L0` và nửa phải `R0`, mỗi nửa 32 bit.

**Bước 3.** Thực hiện 16 vòng Feistel theo công thức:

```text
L(i) = R(i-1)
R(i) = L(i-1) XOR f( R(i-1), K(i) )
```

**Bước 4.** Sau vòng 16, hoán đổi hai nửa thành `R16 || L16`, rồi đưa qua **hoán vị cuối FP** (Final Permutation, là nghịch đảo của IP) để được bản mã 64 bit.

#### Hàm Feistel f(R, K)

Hàm `f` gồm bốn bước:

1. **Mở rộng E:** mở rộng `R` từ 32 bit lên 48 bit bằng cách nhân đôi một số bit.

2. **Trộn khoá:** XOR kết quả 48 bit với khoá con `K(i)` 48 bit.

3. **Thế S-box:** chia 48 bit thành 8 nhóm 6 bit, mỗi nhóm đi qua một S-box (6 bit vào, 4 bit ra) và cho ra tổng cộng 32 bit. Đây là thành phần **phi tuyến** duy nhất của DES.

4. **Hoán vị P:** hoán vị 32 bit đầu ra.

#### Sinh khoá con (Key Schedule)

**Bước 1.** Khoá 64 bit đi qua hoán vị **PC-1** (bỏ 8 bit kiểm tra) để còn 56 bit, chia thành hai nửa `C0` và `D0`, mỗi nửa 28 bit.

**Bước 2.** Ở mỗi vòng, `C` và `D` được **dịch vòng trái** 1 hoặc 2 bit theo bảng: `1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1`.

**Bước 3.** Ghép `C(i) || D(i)` rồi qua hoán vị nén **PC-2** để được khoá con `K(i)` 48 bit.

#### Quy trình giải mã DES

Nhờ cấu trúc Feistel, giải mã **dùng lại đúng thuật toán mã hoá**, chỉ khác thứ tự khoá con được đảo ngược: `K16, K15, ..., K1`.

#### Đánh giá DES

- Không gian khoá chỉ `2^56`, hiện nay có thể bị **vét cạn** trong thời gian ngắn, nên DES **không còn an toàn**.

- **3DES (Triple DES)** khắc phục tạm thời bằng cách áp dụng DES ba lần theo dạng `C = E(K3, D(K2, E(K1, P)))` (EDE), nhưng chậm và đã bị NIST loại khỏi sử dụng.

### 1.3. Thuật toán AES

**AES (Advanced Encryption Standard)** dựa trên thuật toán Rijndael, được NIST chọn làm chuẩn năm 2001 (FIPS 197). AES dùng cấu trúc **mạng thay thế - hoán vị (SPN)** thay cho Feistel.

| Thông số | AES-128 | AES-192 | AES-256 |
|---|---|---|---|
| Kích thước khối | 128 bit | 128 bit | 128 bit |
| Độ dài khoá | 128 bit | 192 bit | 256 bit |
| Số vòng `Nr` | 10 | 12 | 14 |
| Số từ khoá `Nk` (32 bit) | 4 | 6 | 8 |

#### Ma trận trạng thái (State)

Khối 16 byte được xếp **theo cột** vào ma trận 4×4 byte:

```text
| b0  b4  b8   b12 |
| b1  b5  b9   b13 |
| b2  b6  b10  b14 |
| b3  b7  b11  b15 |
```

#### Bốn phép biến đổi trong mỗi vòng

**1. SubBytes** (phép thế byte)

Mỗi byte được thay bằng giá trị tra từ **S-box**. S-box được xây dựng bằng cách lấy nghịch đảo nhân của byte trong trường hữu hạn `GF(2^8)` (đa thức bất khả quy `x^8 + x^4 + x^3 + x + 1`), sau đó áp dụng một phép biến đổi affine. Đây là bước phi tuyến của AES.

**2. ShiftRows** (dịch hàng)

Hàng `r` của ma trận được dịch vòng trái `r` byte (hàng 0 giữ nguyên, hàng 1 dịch 1, hàng 2 dịch 2, hàng 3 dịch 3).

```text
Trước:                Sau:
a0 a1 a2 a3           a0 a1 a2 a3
b0 b1 b2 b3    ──►    b1 b2 b3 b0
c0 c1 c2 c3           c2 c3 c0 c1
d0 d1 d2 d3           d3 d0 d1 d2
```

**3. MixColumns** (trộn cột)

Mỗi cột được nhân với một ma trận cố định trong `GF(2^8)`:

```text
| 02 03 01 01 |   | s0 |
| 01 02 03 01 | × | s1 |
| 01 01 02 03 |   | s2 |
| 03 01 01 02 |   | s3 |
```

Phép này khuếch tán dữ liệu: mỗi byte đầu ra phụ thuộc vào cả 4 byte đầu vào của cột.

**4. AddRoundKey** (cộng khoá vòng)

XOR trạng thái với khoá vòng 128 bit tương ứng.

#### Quy trình mã hoá AES

```text
AddRoundKey(K0)
Lặp Nr-1 vòng:   SubBytes → ShiftRows → MixColumns → AddRoundKey(Ki)
Vòng cuối:       SubBytes → ShiftRows → AddRoundKey(K_Nr)      (không có MixColumns)
```

#### Quy trình giải mã AES

Thực hiện các phép nghịch đảo theo thứ tự ngược lại:

```text
AddRoundKey(K_Nr)
Lặp Nr-1 vòng:   InvShiftRows → InvSubBytes → AddRoundKey(Ki) → InvMixColumns
Vòng cuối:       InvShiftRows → InvSubBytes → AddRoundKey(K0)
```

Trong đó:

- `InvShiftRows` dịch vòng **phải**.

- `InvSubBytes` dùng S-box nghịch đảo.

- `InvMixColumns` nhân với ma trận nghịch đảo `{0E, 0B, 0D, 09}`.

#### Sinh khoá vòng (Key Expansion)

Từ khoá gốc, AES-128 sinh ra 44 từ 32 bit (tức 11 khoá vòng, mỗi khoá 16 byte). Với mỗi từ `w[i]`:

- Nếu `i` chia hết cho `Nk`: `w[i] = w[i-Nk] XOR SubWord(RotWord(w[i-1])) XOR Rcon[i/Nk]`.

- Ngược lại: `w[i] = w[i-Nk] XOR w[i-1]`.

Trong đó `RotWord` xoay vòng 4 byte của từ sang trái 1 byte, `SubWord` áp dụng S-box lên từng byte, và `Rcon` là hằng số vòng (`01, 02, 04, 08, 10, 20, 40, 80, 1B, 36`).

#### So sánh DES và AES

| Tiêu chí | DES | AES |
|---|---|---|
| Cấu trúc | Mạng Feistel | Mạng SPN |
| Khối | 64 bit | 128 bit |
| Khoá hiệu dụng | 56 bit | 128 / 192 / 256 bit |
| Số vòng | 16 | 10 / 12 / 14 |
| Mức an toàn | Đã bị phá bằng vét cạn | An toàn, là chuẩn hiện hành |
| Giải mã | Cùng thuật toán, đảo thứ tự khoá | Dùng các phép nghịch đảo |

### 1.4. Cài đặt AES-128 bằng C++

Cài đặt gồm hai phần: mã hoá/giải mã **một khối 16 byte**, và chế độ **CBC** kèm đệm **PKCS#7** để xử lý dữ liệu có độ dài bất kỳ.

**Lưu ý:** S-box được **tính trực tiếp** từ định nghĩa toán học (nghịch đảo trong `GF(2^8)` và phép biến đổi affine) thay vì gõ tay bảng 256 phần tử, giúp tránh sai sót.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/31f36d58-672d-43a0-9bc4-c1d90ee8cb30" />

**Kết quả mong đợi ở phần 1:** bản mã phải trùng `69c4e0d86a7b0430d8cdb78070b4c55a`, khớp với ví dụ trong chuẩn FIPS-197 (Appendix C.1).

#### Lưu ý về an toàn khi triển khai thực tế

- Cài đặt trên chỉ nhằm **mục đích học tập**. Trong sản phẩm thực tế nên dùng thư viện đã được kiểm chứng như OpenSSL hoặc libsodium.

- **Không dùng chế độ ECB**, vì các khối bản rõ giống nhau cho ra các khối bản mã giống nhau, làm lộ cấu trúc dữ liệu.

- **IV phải ngẫu nhiên** (sinh bằng bộ sinh số ngẫu nhiên an toàn mật mã) và không dùng lại cùng khoá.

- Nên ưu tiên chế độ **AES-GCM** vì vừa mã hoá vừa xác thực toàn vẹn dữ liệu. CBC không tự phát hiện việc bản mã bị sửa đổi.

---

## 2. Tìm hiểu về thuật toán mã hoá bất đối xứng RSA nguyên lý sinh cặp khoá bí mật, công khai


**RSA** do Rivest, Shamir và Adleman công bố năm 1977. Đây là thuật toán mã hoá **khoá công khai**: mỗi người dùng có một **cặp khoá** gồm khoá công khai (public key) và khoá bí mật (private key).

Độ an toàn của RSA dựa trên **bài toán phân tích số nguyên lớn thành thừa số nguyên tố**: nhân hai số nguyên tố lớn rất dễ, nhưng tìm lại hai thừa số từ tích của chúng là bài toán cực kỳ khó.

### 2.1. Nguyên lý sinh cặp khoá (công khai / bí mật)

**Bước 1.** Chọn hai số nguyên tố lớn `p` và `q` (`p ≠ q`), độ dài xấp xỉ nhau, chọn ngẫu nhiên.

**Bước 2.** Tính modulus:

```text
n = p × q
```

**Bước 3.** Tính hàm Euler:

```text
φ(n) = (p - 1) × (q - 1)
```

**Bước 4.** Chọn số mũ công khai `e` sao cho:

```text
1 < e < φ(n)   và   gcd(e, φ(n)) = 1
```

Giá trị thường dùng là `e = 65537` (`2^16 + 1`).

**Bước 5.** Tính số mũ bí mật `d` là **nghịch đảo modulo** của `e`:

```text
d × e ≡ 1 (mod φ(n))
```

`d` được tính bằng **thuật toán Euclid mở rộng**.

**Kết quả:**

| Loại khoá | Thành phần | Ai giữ |
|---|---|---|
| Khoá công khai | `PU = (e, n)` | Công bố cho mọi người |
| Khoá bí mật | `PR = (d, n)` | Chỉ chủ sở hữu giữ kín (`p`, `q`, `φ(n)` cũng phải giấu) |

### 2.2. Quy trình mã hoá và giải mã

Bản rõ `M` được biểu diễn thành số nguyên thoả `0 ≤ M < n`.

**Mã hoá** (dùng khoá công khai):

```text
C = M^e mod n
```

**Giải mã** (dùng khoá bí mật):

```text
M = C^d mod n
```

#### Vì sao giải mã đúng?

Do `e × d ≡ 1 (mod φ(n))`, tồn tại số nguyên `k` sao cho `e × d = 1 + k × φ(n)`. Khi đó, theo định lý Euler (với `gcd(M, n) = 1`):

```text
C^d = M^(e×d) = M × (M^φ(n))^k ≡ M × 1^k ≡ M (mod n)
```

Kết quả cũng đúng khi `gcd(M, n) ≠ 1` (chứng minh bằng định lý phần dư Trung Hoa).

#### Vì sao an toàn?

Kẻ tấn công biết `(e, n)` nhưng muốn tính `d` thì cần `φ(n)`, mà điều đó đòi hỏi phân tích `n` thành `p × q`. Với `n` đủ lớn thì việc này không khả thi.

Khuyến nghị hiện nay: `n` dài **tối thiểu 2048 bit**, ưu tiên 3072 bit trở lên cho dữ liệu cần bảo vệ lâu dài.

### 2.3. Ví dụ số và cài đặt C++

#### Ví dụ với số nhỏ

| Bước | Giá trị |
|---|---|
| Chọn `p`, `q` | `p = 61`, `q = 53` |
| `n = p × q` | `3233` |
| `φ(n) = 60 × 52` | `3120` |
| Chọn `e` (nguyên tố cùng nhau với 3120) | `e = 17` |
| `d = e⁻¹ mod 3120` | `d = 2753` (vì `17 × 2753 = 46801 = 15 × 3120 + 1`) |
| Khoá công khai | `(17, 3233)` |
| Khoá bí mật | `(2753, 3233)` |
| Mã hoá `M = 65` | `C = 65^17 mod 3233 = 2790` |
| Giải mã | `M = 2790^2753 mod 3233 = 65` |



## 3. Trình bày các mô hình hình áp dụng thuật toán RSA xác thực người gửi, xác thực người nhận, cả 2 so sánh thời gian mã hoá/giải mã của RSA với AES đưa ra các dùng kết hợp sức mạnh của RSA và AES.

Vì RSA có hai khoá với tính chất **đối xứng về vai trò** (dùng khoá này mã hoá thì dùng khoá kia giải mã), ta có thể đảo thứ tự sử dụng khoá để đạt các mục tiêu an toàn khác nhau.

Ký hiệu: người gửi là **A**, người nhận là **B**. `PU_A`, `PR_A` là khoá công khai và bí mật của A. `PU_B`, `PR_B` là của B.

### 3.1. Ba mô hình áp dụng

#### Mô hình 1: Bảo mật, đảm bảo chỉ người nhận đọc được (xác thực người nhận)

A mã hoá bằng **khoá công khai của B**. Chỉ B giữ khoá bí mật tương ứng nên chỉ B giải mã được.

```text
A:  C = E(PU_B, M)
B:  M = D(PR_B, C)
```

```text
   A ──[ M ]──► Mã hoá bằng PU_B ──► C ────────────► Giải mã bằng PR_B ──► [ M ]── B
```

- **Đạt được:** tính **bảo mật** (confidentiality). Chỉ đúng người nhận B đọc được nội dung.

- **Không đạt:** B không biết chắc ai đã gửi, vì `PU_B` là công khai nên bất kỳ ai cũng có thể gửi.

#### Mô hình 2: Xác thực người gửi (chữ ký số)

A mã hoá bằng **khoá bí mật của A**. Bất kỳ ai cũng dùng `PU_A` để giải mã và kiểm tra.

```text
A:  S = E(PR_A, M)
B:  M = D(PU_A, S)
```

```text
   A ──[ M ]──► Mã hoá bằng PR_A ──► S ────────────► Giải mã bằng PU_A ──► [ M ]── B
```

- **Đạt được:** **xác thực** nguồn gốc (chỉ A có `PR_A`), **toàn vẹn** và **chống chối bỏ** (non-repudiation).

- **Không đạt:** không bảo mật, vì ai có `PU_A` (công khai) cũng đọc được nội dung.

- **Thực tế:** thay vì ký toàn bộ thông điệp, A tính giá trị **băm** `H = Hash(M)` rồi ký giá trị băm: `S = E(PR_A, H)`. Người nhận tính lại `Hash(M)` và so sánh với `D(PU_A, S)`. Cách này nhanh hơn nhiều và không bị giới hạn kích thước thông điệp.

#### Mô hình 3: Kết hợp cả hai (vừa bảo mật vừa xác thực)

A **ký bằng khoá bí mật của A** trước, sau đó **mã hoá bằng khoá công khai của B**.

```text
A:  C = E(PU_B, E(PR_A, M))
B:  M = D(PU_A, D(PR_B, C))
```

```text
   A ──[ M ]──► ký bằng PR_A ──► mã hoá bằng PU_B ──► C
                                                       │
   B ◄──[ M ]── kiểm tra bằng PU_A ◄── giải mã bằng PR_B ◄┘
```

- **Đạt được:** bảo mật, xác thực người gửi, toàn vẹn và chống chối bỏ.

- **Nhược điểm:** phải thực hiện RSA **hai lần** ở mỗi phía, chi phí tính toán cao.

#### Bảng tóm tắt

| Mô hình | Mã hoá bằng | Giải mã bằng | Bảo mật | Xác thực người gửi |
|---|---|---|:---:|:---:|
| 1. Xác thực/bảo mật cho người nhận | `PU_B` | `PR_B` | Có | Không |
| 2. Xác thực người gửi | `PR_A` | `PU_A` | Không | Có |
| 3. Cả hai | `PR_A` rồi `PU_B` | `PR_B` rồi `PU_A` | Có | Có |


### 3.2. So sánh thời gian mã hoá/giải mã giữa RSA và AES

RSA thực hiện **phép luỹ thừa modulo với số nguyên rất lớn** (hàng nghìn bit), còn AES chỉ dùng các phép XOR, tra bảng và dịch bit trên khối 128 bit. Vì vậy AES nhanh hơn RSA rất nhiều.

| Tiêu chí | AES-128 | RSA-2048 |
|---|---|---|
| Loại | Đối xứng | Bất đối xứng |
| Khoá | 1 khoá bí mật 128 bit | Cặp khoá, modulus 2048 bit |
| Phép toán chính | XOR, tra S-box, nhân trong `GF(2^8)` | Luỹ thừa modulo số 2048 bit |
| Tốc độ (bậc độ lớn) | Hàng trăm MB/s đến hàng GB/s mỗi lõi CPU (nhanh nhất khi có tập lệnh AES-NI) | Vài chục đến vài nghìn thao tác mỗi giây, tương đương dưới **1 MB/s** |
| Mã hoá và giải mã | Hai chiều gần như bằng nhau | **Bất đối xứng:** mã hoá (số mũ `e` nhỏ) nhanh, giải mã/ký (số mũ `d` lớn) **chậm hơn hàng chục lần** |
| Kích thước dữ liệu mỗi lần | Bất kỳ (chia khối 16 byte) | Bị giới hạn bởi `n`: tối đa khoảng 245 byte với đệm PKCS#1 v1.5, ít hơn với OAEP |
| Phân phối khoá | Khó: cần kênh an toàn | Dễ: khoá công khai có thể công bố |
| Ứng dụng chính | Mã hoá dữ liệu lớn | Trao đổi khoá, chữ ký số, chứng chỉ |

**Kết luận:** AES nhanh hơn RSA **từ hàng trăm đến hàng nghìn lần** khi mã hoá cùng lượng dữ liệu. Các con số chính xác phụ thuộc phần cứng, thư viện và độ dài khoá, nên cần đo trên máy của mình.

#### Cách đo thực tế bằng OpenSSL

Cách đơn giản và tin cậy nhất để có số liệu là dùng công cụ `openssl speed`:

```bash
# Đo AES-128 (số liệu tính bằng byte/giây theo từng cỡ khối)
openssl speed -evp aes-128-cbc

# Đo RSA 2048 bit (số phép ký/giây và kiểm tra/giây)
openssl speed rsa2048
```

Cách đọc kết quả:

- Với AES: cột kích thước lớn (ví dụ 8192 bytes) cho thấy thông lượng tối đa.

- Với RSA: `sign/s` là số lần dùng khoá **bí mật** mỗi giây (chậm), `verify/s` là số lần dùng khoá **công khai** mỗi giây (nhanh hơn nhiều).

Quy đổi để so sánh: nếu RSA-2048 giải mã khoảng 1000 lần/giây và mỗi lần xử lý tối đa khoảng 200 byte thì thông lượng chỉ khoảng 0,2 MB/s, trong khi AES đạt hàng trăm MB/s trở lên.

### 3.3. Mô hình kết hợp RSA và AES (mã hoá lai)

Mỗi thuật toán có điểm mạnh riêng:

- **AES:** nhanh, xử lý được dữ liệu lớn, nhưng gặp khó khăn khi chia sẻ khoá.

- **RSA:** giải quyết được bài toán phân phối khoá và chữ ký số, nhưng chậm và giới hạn kích thước dữ liệu.

**Ý tưởng mã hoá lai (hybrid encryption):** dùng **AES để mã hoá dữ liệu**, dùng **RSA để bảo vệ khoá AES** (và để ký).

#### Quy trình người gửi A

**Bước 1.** Sinh ngẫu nhiên một **khoá phiên** AES `K` (ví dụ 128 hoặc 256 bit) cùng vector khởi tạo `IV`.

**Bước 2.** Mã hoá dữ liệu bằng AES: `C = AES_K(M)`.

**Bước 3.** Mã hoá khoá phiên bằng RSA với **khoá công khai của B**: `EK = RSA(PU_B, K)`.

**Bước 4.** (Tuỳ chọn, để xác thực người gửi) Tính `H = Hash(M)` rồi ký bằng khoá bí mật của A: `S = RSA(PR_A, H)`.

**Bước 5.** Gửi gói tin `{ EK, IV, C, S }` cho B.

#### Quy trình người nhận B

**Bước 1.** Giải mã khoá phiên: `K = RSA⁻¹(PR_B, EK)`.

**Bước 2.** Giải mã dữ liệu: `M = AES⁻¹_K(C)`.

**Bước 3.** Tính lại `Hash(M)` và so sánh với `RSA⁻¹(PU_A, S)` để xác thực người gửi và kiểm tra toàn vẹn.

#### Sơ đồ

```text
                         NGƯỜI GỬI (A)                                        NGƯỜI NHẬN (B)

   Dữ liệu M ──► [AES-CBC, khoá phiên K, IV] ──────────► C ─────────────────► [AES giải mã, K] ──► M
                                                                                     ▲
   Khoá phiên K ──► [RSA mã hoá bằng PU_B] ─────────► EK ──► [RSA giải mã bằng PR_B] ┘  (thu được K)

   Hash(M) ──► [RSA ký bằng PR_A] ───────────────────► S ──► [RSA kiểm tra bằng PU_A] ──► so khớp Hash(M)
```

#### Lợi ích

| Vấn đề | Cách giải quyết |
|---|---|
| Dữ liệu lớn, cần tốc độ | AES xử lý toàn bộ dữ liệu |
| Trao đổi khoá qua kênh không an toàn | RSA chỉ mã hoá khoá AES ngắn (16 đến 32 byte) |
| Xác thực người gửi, chống chối bỏ | Chữ ký số RSA trên giá trị băm |
| Khoá dùng một lần | Khoá phiên AES sinh mới cho mỗi lần gửi, lộ một khoá chỉ ảnh hưởng một phiên |

Mô hình này là nền tảng của nhiều giao thức thực tế như **TLS/HTTPS**, **PGP/GPG** và **S/MIME**.

