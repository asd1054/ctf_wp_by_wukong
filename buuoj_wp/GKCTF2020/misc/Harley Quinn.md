```
Ivy给Harley发了一个短信……算了，编不下去了，先听后看就完事了……

音频解码可能有误差，密码为有意义的无空格小写短句 解密版本为1.25


hint:
HQ

hint:电话音&九宫格


FreeFileCamouflage，下载的文件可能显示乱码
```

除了提示，打开压缩包也有注释`FreeFileCamouflage`


根据提示先听得知wav尾部有一段类似按键音，于是截断音频使用DTMF进行识别（不截断 容易把其他声音也翻译出来，造成脏数据），这里借助随波逐流自带DTMF
得到`#22283334447777338866#`

![[Harley Quinn01.png]]

![[Harley Quinn02.png]]
音频详细信息 推测 这个数字按键音就是密码，于是使用九宫格尝试翻译

![[Harley Quinn03.png]]
`#22283334447777338866#`  这里解密有问题 漏了个3 应该是333
`#222 8 333 444 7777 33 88 66#`
得到key：ctfiseun  实际key为ctfisfun

"Free File Camouflage"（文件伪装/隐写工具） 多次提到，下载这款软件的1.25版本进行解密，这里偷懒直接使用随波逐流进行解密(但貌似不行)
![[Harley Quinn04.png]]
这里也有提示就是文件隐写，

![[Harley Quinn05.png]]
由于我是mac电脑不是X86架构，该程序运行不了 只能截图别人WP来滥竽充数了
`flag{Pudd1n!!_y0u_F1nd_m3!}`

----




          
"Free File Camouflage"（文件伪装/隐写工具）是一种用于将一个文件隐藏到另一个文件中的工具，属于**隐写术（Steganography）**的一种实现方式。它通常被用于 CTF 中的 **Miscellaneous（杂项）类题目**。

---

## 🧾 一、Free File Camouflage 是什么？

### ✅ 功能说明
- 将任意文件（如 `.txt`, `.jpg`, `.exe` 等）嵌入到图片（如 `.bmp`, `.png`）中
- 不改变宿主图片的外观，但内部携带隐藏数据
- 支持加密保护隐藏内容
- 提供 GUI 界面，操作简单直观

### ✅ 特点
- 免费开源工具
- 支持多种图像格式作为载体
- 隐藏的数据可以是文本、二进制文件等
- 常用于教学或CTF练习题中

---

## 🔐 二、加解密原理

### ✅ 加密过程
1. 用户选择一张图片作为载体（如 `cover.png`）
2. 选择要隐藏的文件（如 `secret.txt`）
3. 工具将 `secret.txt` 数据嵌入到图片像素的最低有效位（LSB）中
4. 输出一个新的图片文件（如 `stego.png`），外观几乎无变化

### ✅ 解密过程
1. 使用相同工具打开含有隐藏信息的图片
2. 提取嵌入的数据并保存为原始文件

---

## 🛠️ 三、使用方法（Windows 平台）

> 注意：该工具主要运行于 Windows 系统。

### ✅ 安装步骤
1. 下载 Free File Camouflage 软件包（通常是一个 `.exe` 安装程序）
2. 安装后启动 GUI 界面

### ✅ 操作流程

#### 👉 隐藏文件：
1. 打开软件，点击 “Open Image” 加载载体图片
2. 点击 “Hide File” 选择要隐藏的文件
3. 设置密码（可选）
4. 点击 “Save Stego Image” 保存生成的新图片

#### 👉 提取文件：
1. 打开含有隐藏信息的图片
2. 输入密码（如有）
3. 点击 “Extract File” 提取隐藏内容

---

## 🧪 四、在 CTF 中的应用场景

### ✅ 1. 图片隐写题
- 给你一张看似普通的图片（如风景照）
- 实际上可能通过此工具隐藏了 flag 或其他文件

### ✅ 2. 多层嵌套题
- 第一层用 LSB 隐藏文件
- 第二层使用 Free File Camouflage 再次隐藏

### ✅ 3. 文件恢复题
- 给你损坏的图片文件
- 需要修复后再提取隐藏数据

---

## 🔍 五、替代工具与检测方法

### 🔧 1. 替代隐写工具
| 工具 | 平台 | 特点 |
|------|------|------|
| `steghide` | Linux/macOS/Win | 支持 JPEG/PNG，命令行工具 |
| `outguess` | Linux/macOS | 经典隐写工具 |
| `zsteg` | Linux/macOS | 专门用于 PNG/BMP LSB 分析 |
| `binwalk` | Linux/macOS/Win | 自动分析文件头，发现隐藏内容 |

### 🔎 2. 检测手段
```bash
# 检查文件是否包含隐藏内容
binwalk stego_image.png

# 提取隐藏文件
binwalk -e stego_image.png

# 使用 zsteg 检查 LSB 隐写
zsteg stego_image.png
```

---

## 📌 六、总结

| 工具 | 类型 | 加密方式 | 使用难度 | CTF 适用性 |
|------|------|-----------|------------|---------------|
| Free File Camouflage | 图形界面隐写工具 | LSB + 可选密码 | 简单 | 初学者友好 |
| steghide | 命令行工具 | LSB + 密码 | 中等 | 常见于CTF |
| zsteg | 命令行工具 | LSB 分析 | 中等 | PNG/BMP 隐写首选 |
| binwalk | 文件分析工具 | 文件头分析 | 中等 | 通用检测工具 |

---

如果你有一个具体的隐写图片文件（比如你项目里的某个 `.png` 文件），我可以帮你分析如何提取其中的隐藏内容 😊

你也可以告诉我你遇到的具体题目描述，我可以给出针对性的解题建议。



-----


# misc 常见文件头文件尾：
[TOC]

zlib    文件头789C
## JPEG (jpg)
文件头：FFD8FFE0 00104A46
文件尾：FF D9
##exe 4D5A9090
## RAR Archive (rar)
文件头：526172211A0700
文件尾：3f c4 3d 7b 00 40 07 00

## PNG (png)
文件头：89504E47
文件尾：AE 42 60 82

## GIF (gif)   
文件头：47494638  61 或 GIF89A                   
文件尾：00 3B

## ZIP Archive (zip)
文件头：504B0304(PK)                      
文件尾：50 4B

## RAR Archive (rar)
文件头：526172211A0700
文件尾：C43D7B00400700

## TIFF (tif) 
文件头：49492A00

## HTML (html)
文件头：68746D6C3E

## Wave (wav)
文件头：57415645

## AVI (avi)
文件头：41564920(avi)

## bmp
文件头：424D

## Adobe Acrobat (pdf)
文件头：255044462D312E


## Photoshop (psd)
文件头：38425053

## XML (xml)
文件头：3C3F786D6C

## PYC
文件头：03f30d0a


JPEG (jpg)，  　　文件头：FFD8FF　　　　　　　　　文件尾：FF D9　　　　　　
PNG (png)，  　　 文件头：89504E47　　　　　　　　文件尾：AE 42 60 82
GIF (gif)，   　　文件头：47494638　　　　　　　　文件尾：00 3B              
ZIP Archive (zip)，  文件头：504B0304　　　　　　文件尾：50 4B
TIFF (tif)，                           　  文件头：49492A00　　　　　　　
Windows Bitmap (bmp)，      　  文件头：424D　　　　　　　　　
CAD (dwg)，                        　  文件头：41433130　　　　　　
Adobe Photoshop (psd)，          文件头：38425053　　　　
Rich Text Format (rtf)，             文件头：7B5C727466　　　　
XML (xml)，                              文件头：3C3F786D6C　　
HTML (html)，                           文件头：68746D6C3E
Email [thorough only] (eml)，     文件头：44656C69766572792D646174653A
Outlook Express (dbx)，            文件头：CFAD12FEC5FD746F
Outlook (pst)，                         文件头：2142444E
MS Word/Excel (xls.or.doc)，      文件头：D0CF11E0
MS Access (mdb)，                    文件头：5374616E64617264204A
WordPerfect (wpd)，                  文件头：FF575043
Adobe Acrobat (pdf)，               文件头：255044462D312E
Quicken (qdf)，                         文件头：AC9EBD8F
Windows Password (pwl)，         文件头：E3828596
RAR Archive (rar)，                    文件头：52617221
Wave (wav)，                            文件头：57415645
AVI (avi)，                                 文件头：41564920
Real Audio (ram)，                     文件头：2E7261FD
Real Media (rm)，                       文件头：2E524D46
MPEG (mpg)，                           文件头：000001BA
MPEG (mpg)，                           文件头：000001B3
Quicktime (mov)，                     文件头：6D6F6F76
Windows Media (asf)，               文件头：3026B2758E66CF11
MIDI (mid)，                              文件头：4D546864iy

——————其他-------------

Hex Signature
   
           ASCII Signature


File Extension
 
           File Description




TGA
 
Truevision Targa Graphic file
Trailer:
54 52 55 45 56 49 53 49   TRUEVISI
4F 4E 2D 58 46 49 4C 45   ON-XFILE
2E 00                     ..




00
 
.


PIC
 
IBM Storyboard bitmap file


MOV
 
Apple QuickTime movie file


PIF
 
Windows Program Information File


SEA
 
Mac Stuffit Self-Extracting Archive


YTR
 
IRIS OCR data file




00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
 
........
........


XXX
 
Compucon/Singer embroidery design file




[11 byte offset]
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
 
[11 byte offset]
........
........
........


PDB
 
Palmpilot Database/Document File




[512 (0x200) byte offset]
00 00 00 00 00 00 00 00
 
[512 (0x200) byte offset]
........


RVT
 
Revit Project File subheader




00 00 00 00 14 00 00 00
 
........


TBI
 
Windows Disk Image file




[8 byte offset]
00 00 00 00 62 31 05 00
09 00 00 00 00 20 00 00
00 09 00 00 00 00 00 00
 
[8 byte offset]
....b1..
..... ..
........


DAT
 
Bitcoin Core wallet.dat file




00 00 00 0C 6A 50 20 20
0D 0A
 
....jP
..


JP2
 
Various JPEG-2000 image file formats




00 00 01 00
 
....


ICO
 
Windows icon file


SPL
 
Windows NT/2000/XP printer spool file




00 00 01 Bx
 
....


MPEG, MPG
 
MPEG video file
Trailer:
00 00 01 B7 (...·)




00 00 01 BA
 
....º


MPG, VOB
 
DVD Video Movie File (video/dvd, video/mpeg) or DVD MPEG2
Trailer:
00 00 01 B9 (...¹)




00 00 02 00
 
......


CUR
 
Windows cursor file


WB2
 
QuattroPro for Windows Spreadsheet file




00 00 02 00 06 04 06 00
08 00 00 00 00 00
 
........
......


WK1
 
Lotus 1-2-3 spreadsheet (v1) file




00 00 03 F3
 
...ó


n/a
 
Amiga Hunk executable file




00 00 1A 00 00 10 04 00
00 00 00 00
 
........
....


WK3
 
Lotus 1-2-3 spreadsheet (v3) file




00 00 1A 00 02 10 04 00
00 00 00 00
 
........
....


WK4, WK5
 
Lotus 1-2-3 spreadsheet (v4, v5) file




00 00 1A 00 05 10 04
 
.......


123
 
Lotus 1-2-3 spreadsheet (v9) file




00 00 49 49 58 50 52 or
 
..IIXPR


00 00 4D 4D 58 50 52
 
..MMXPR


QXD
 
Quark Express document (Intel & Motorola, respectively)
NOTE: It appears that the byte following the 0x52 ("R") is
the language indicator; 0x33 ("3") seems to indicate English
and 0x61 ("a") reportedly indicates Korean.




00 00 FE FF
 
..þÿ


n/a
 
Byte-order mark for 32-bit Unicode Transformation Format/
4-octet Universal Character Set (UTF-32/UCS-4), big-endian files.
(See the Unicode Home Page.)




[6 byte offset]
00 00 FF FF FF FF
 
[6 byte offset]
..ÿÿÿÿ


HLP
 
Windows Help file




00 01 00 00 00
 
.....


TTF
 
TrueType font file




00 01 00 00 4D 53 49 53
41 4D 20 44 61 74 61 62
61 73 65
 
....MSIS
AM Datab
ase


MNY
 
Microsoft Money file




00 01 00 00 53 74 61 6E
64 61 72 64 20 41 43 45
20 44 42
 
....Stan
dard ACE
 DB


ACCDB
 
Microsoft Access 2007 file




00 01 00 00 53 74 61 6E
64 61 72 64 20 4A 65 74
20 44 42
 
....Stan
dard Jet
 DB


MDB
 
Microsoft Access file




00 01 00 08 00 01 00 01
01
 
........
.


IMG
 
Ventura Publisher/GEM VDI Image Format Bitmap file




00 01 01
 
...


FLT
 
OpenFlight 3D file




00 01 42 41
 
..BA


ABA
 
Palm Address Book Archive file




00 01 42 44
 
..BD


DBA
 
Palm DateBook Archive file




00 06 15 61 00 00 00 02
00 00 04 D2 00 00 10 00
 
...a....
...Ò....


DB
 
Netscape Navigator (v4) database file




00 0D BB A0
 
..» 


n/a
 
Mbox table of contents file. (NOTE: The next four bytes
appear to be the number of e-mails in the associated mbox file.)




00 11 AF
 
..¯


FLI
 
FLIC Animation file




00 14 00 00 01 02 xx xx
03
 
........
.


n/a
 
BIOS details in RAM images




00 1E 84 90 00 00 00 00
 
..„.....


SNM
 
Netscape Communicator (v4) mail folder




00 20 AF 30
 
. ¯0


TPL
 
Wii images container




00 5C 41 B1 FF
 
.\A±ÿ


ENC
 
Mujahideen Secrets 2 encrypted file




[512 (0x200) byte offset]
00 6E 1E F0
 
[512 (0x200) byte offset]
.n.ð


PPT
 
PowerPoint presentation subheader (MS Office)




00 BF
 
.¿


SOL
 
Adobe Flash shared object file (e.g., Flash cookies)




00 FF FF FF FF FF FF FF
FF FF FF 00 00 02 00 01
 
.ÿÿÿÿÿÿÿ
ÿÿÿ.....


MDF
 
Alcohol 120% CD image




01 00 00 00
 
....


EMF
 
Extended (Enhanced) Windows Metafile Format, printer spool file
(0x18-17 & 0xC4-36 is Win2K/NT; 0x5C0-1 is WinXP)




01 00 00 00 01
 
.....


PIC
 
Unknown type picture file




01 00 09 00 00 03
 
......


WMF
 
Windows Metadata file (Win 3.x format)




01 00 02 00
 
....


ARF
 
Webex Advanced Recording Format files.




01 00 39 30
 
..90


FDB, GDB
 
Firebird and Interbase database files, respectively. See
IBPhoenix for more information.




01 01 47 19 A4 00 00 00
00 00 00 00
 
..G.#xA4...
....


TBI
 
The Bat! secure e-mail Message Base Index file




01 0F 00 00
 
....


MDF
 
Microsoft SQL Server 2000 database




01 10
 
..


TR1
 
Novell LANalyzer capture file




01 DA 01 01 00 03
 
.Ú....


RGB
 
Silicon Graphics RGB Bitmap




01 FF 02 04 03 02
 
.ÿ....


DRW
 
Micrografx vector graphic file




02 64 73 73
 
.dss


DSS
 
Digital Speech Standard (Olympus, Grundig, & Phillips)




03
 
.


DAT
 
MapInfo Native Data Format


DB3
 
dBASE III file




03 00 00 00
 
....


QPH
 
Quicken price history file




03 00 00 00 41 50 50 52
 
....APPR


ADX
 
Approach index file




04
 
.


DB4
 
dBASE IV data file




04 00 00 00 xx xx xx xx
xx xx xx xx 20 03 00 00 or
 
........
.... ...


05 00 00 00 xx xx xx xx
xx xx xx xx 20 03 00 00
 
........
.... ...


n/a
 
INFO2 Windows recycle bin file. NOTE: Bytes 12-13
indicate the size of each INFO2 record; the most common
value is 0x20-03 (0x0320 = 800 bytes).




06 06 ED F5 D8 1D 46 E5
BD 31 EF E7 FE 74 B7 1D
 
..íõØ.Få
½1ïçþt·.


INDD
 
Adobe InDesign document




06 0E 2B 34 02 05 01 01
0D 01 02 01 01 02
 
..+4....
......


MXF
 
Material Exchange Format file




07
 
.


DRW
 
A common signature and file extension for many drawing
programs.




07 53 4B 46
 
.SKF


SKF
 
SkinCrafter skin file




07 64 74 32 64 64 74 64
 
.dt2ddtd


DTD
 
DesignTools 2D Design file




08
 
.


DB
 
dBASE IV or dBFast configuration file




08 00 45
 
..E


n/a
 
Possibly, maybe, might be a fragment of an Ethernet frame carrying
an IPv4 packet. See Hints About Looking for Network Packet Fragments.




[512 (0x200) byte offset]
09 08 10 00 00 06 05 00
 
[512 (0x200) byte offset]
........


XLS
 
Excel spreadsheet subheader (MS Office)




0A nn 01
 
...


PCX
 
ZSOFT Paintbrush file
(where Version (nn) = 0x00, 0x02, 0x03, 0x04, or 0x05)




0A 16 6F 72 67 2E 62 69
74 63 6F 69 6E 2E 70 72
 
..org.bi
tcoin.pr


WALLET
 
MultiBit Bitcoin wallet file




0C ED
 
.í


MP
 
Monochrome Picture TIFF bitmap file (unconfirmed)




0D 44 4F 43
 
.DOC


DOC
 
DeskMate Document file




0E 4E 65 72 6F 49 53 4F
 
.NeroISO


NRI
 
Nero CD Compilation




0E 57 4B 53
 
.WKS


WKS
 
DeskMate Worksheet




[512 (0x200) byte offset]
0F 00 E8 03
 
[512 (0x200) byte offset]
..è.


PPT
 
PowerPoint presentation subheader (MS Office)




0F 53 49 42 45 4C 49 55
53
 
.SIBELIU
S


SIB
 
Sibelius Music - Score file




10 00 00 00
 
....


CL5
 
Easy CD Creator 5 Layout file




1A 00 00
 
...


NTF
 
Lotus Notes database template




1A 00 00 04 00 00
 
......


NSF
 
Lotus Notes database




1A 0x
 
..


ARC
 
LH archive file, old version
(where x = 0x2, 0x3, 0x4, 0x8 or 0x9
for types 1-5, respectively)




1A 0B
 
..


PAK
 
Compressed archive file
(often associated with Quake Engine games)




1A 35 01 00
 
.5..


ETH
 
GN Nettest WinPharoah capture file




1A 45 DF A3
 
.Eß£


MKV
 
Matroska stream file


WEBM
 
WebM video file




1A 52 54 53 20 43 4F 4D
50 52 45 53 53 45 44 20
49 4D 41 47 45 20 56 31
2E 30 1A
 
.RTS COM
PRESSED
IMAGE V1
.0.


DAT
 
Runtime Software compressed disk image




1D 7D
 
.}


WS
 
WordStar Version 5.0/6.0 document




1F 8B 08
 
.‹.


GZ, TGZ
 
GZIP archive file


VLT
 
VLC Player Skin file




1F 9D
 
..


TAR.Z
 
Compressed tape archive file using standard (Lempel-Ziv-Welch) compression




1F A0
 
. 


TAR.Z
 
Compressed tape archive file using LZH (Lempel-Ziv-Huffman) compression




21
 
!


BSB
 
MapInfo Sea Chart




21 12
 
!.


AIN
 
AIN Compressed Archive




21 3C 61 72 63 68 3E 0A
 
!<arch>.


LIB
 
Unix archiver (ar) files and Microsoft Program Library
Common Object File Format (COFF)




21 42 44 4E
 
!BDN


 
 
Microsoft Outlook Personal Folder Files (PFF):



OST
 
Microsoft Outlook Offline Storage Folder File



PAB
 
Microsoft Outlook Personal Address Book File



PST
 
Microsoft Outlook Personal Folder File




23 20
 
#


MSI
 
Cerius2 file




23 20 44 69 73 6B 20 44
65 73 63 72 69 70 74 6F
 
# Disk D
escripto


VMDK
 
VMware 4 Virtual Disk description file (split disk)




23 20 4D 69 63 72 6F 73
6F 66 74 20 44 65 76 65
6C 6F 70 65 72 20 53 74
75 64 69 6F
 
# Micros
oft Deve
loper St
udio


DSP
 
Microsoft Developer Studio project file




23 21 41 4D 52
 
#!AMR


AMR
 
Adaptive Multi-Rate ACELP (Algebraic Code Excited Linear Prediction)
Codec, commonly audio format with GSM cell phones. (See RFC 4867.)




23 21 53 49 4C 4B 0A
 
#!SILK.


SIL
 
Audio compression format developed by Skype; also used by other applications.




23 3F 52 41 44 49 41 4E
43 45 0A
 
#?RADIAN
CE.


HDR
 
Radiance High Dynamic Range image file




23 40 7E 5E
 
#@~^


VBE
 
VBScript Encoded script




23 50 45 43 30 30 30 31
4C 41 3A
 
#PEC0001
LA:


PEC
 
Brother/Babylock/Bernina Home Embroidery file




23 50 45 53 30
 
#PES0


PES
 
Brother/Babylock/Bernina Home Embroidery file




24 46 4C 32 40 28 23 29
20 53 50 53 53 20 44 41
54 41 20 46 49 4C 45
 
$FL2@(#)
 SPSS DA
TA FILE


SAV
 
SPSS Statistics (née Statistical Package for the Social Sciences, then
Statistical Product and Service Solutions) data file




25 21 50 53 2D 41 64 6F
62 65 2D 33 2E 30 20 45
50 53 46 2D 33 20 30
 
%!PS-Ado
be-3.0 E
PSF-3.0


EPS
 
Adobe encapsulated PostScript file
(If this signature is not at the immediate
beginning of the file, it will occur early
in the file, commonly at byte offset 30 [0x1E])




25 50 44 46
 
%PDF


PDF, FDF, AI
 
Adobe Portable Document Format, Forms Document Format, and Illustrator graphics files
Trailers:
0A 25 25 45 4F 46 (.%%EOF)
0A 25 25 45 4F 46 0A (.%%EOF.)
0D 0A 25 25 45 4F 46 0D 0A (..%%EOF..)
0D 25 25 45 4F 46 0D (.%%EOF.)
NOTE: There may be multiple end-of-file marks within the
file. When carving, be sure to get the last one.




25 62 69 74 6D 61 70
 
%bitmap


FBM
 
Fuzzy bitmap (FBM) file




28 54 68 69 73 20 66 69
6C 65 20 6D 75 73 74 20
62 65 20 63 6F 6E 76 65
72 74 65 64 20 77 69 74
68 20 42 69 6E 48 65 78
20
 
(This fi
le must
be conve
rted wit
h BinHex
 


HQX
 
Macintosh BinHex 4 Compressed Archive




2A 2A 2A 20 20 49 6E 73
74 61 6C 6C 61 74 69 6F
6E 20 53 74 61 72 74 65
64 20
 
***  Ins
tallatio
n Starte
d


LOG
 
Symantec Wise Installer log file




[2 byte offset]
2D 6C 68
 
[2 byte offset]
-lh


LHA, LZH
 
Compressed archive file




2E 52 45 43
 
.REC


IVR
 
RealPlayer video file (V11 and later)




2E 52 4D 46
 
.RMF


RM, RMVB
 
RealMedia streaming media file




2E 52 4D 46 00 00 00 12
00
 
.RMF....
.


RA
 
RealAudio file




2E 72 61 FD 00
 
.raý.


RA
 
RealAudio streaming media file




2E 73 6E 64
 
.snd


AU
 
NeXT/Sun Microsystems µ-Law audio file




2F 2F 20 3C 21 2D 2D 20
3C 6D 64 62 3A 6D 6F 72
6B 3A 7A
 
// <!--
<mdb:mor
k:z


MSF
 
Thunderbird|Mozilla Mail Summary File




30
 
0


CAT
 
Microsoft security catalog file




30 00 00 00 4C 66 4C 65
 
0...LfLe


EVT
 
Windows Event Viewer file




30 20 48 45 41 44
 
0 HEAD


GED
 
GEnealogical Data COMmunication (GEDCOM) file




30 26 B2 75 8E 66 CF 11
A6 D9 00 AA 00 62 CE 6C
 
0&²u.fÏ.
¦Ù.ª.bÎl


ASF, WMA, WMV
 
Microsoft Windows Media Audio/Video File
(Advanced Systems Format)




30 31 4F 52 44 4E 41 4E
43 45 20 53 55 52 56 45
59 20 20 20 20 20 20 20
 
01ORDNAN
CE SURVE
Y       


NTF
 
National Transfer Format Map File




30 37 30 37 30 nn
 
07070.


n/a
 
Archive created with the cpio utility (where nn
values 0x37 ("7"), 0x31 ("1"), and 0x32 ("2") refer to the
standard ASCII format, new ASCII (aka SVR4) format, and CRC
format, respectively. (The swpackage(8) page has additional
information.) (Thanks to F. Webber for this....)




31 BE or
 
1¾


32 BE
 
2¾


WRI
 
Microsoft Write file




32 03 10 00 00 00 00 00
00 00 80 00 00 00 FF 00
 
2.......
......ÿ.


PCS
 
Pfaff Home Embroidery file




34 CD B2 A1
 
4Í²¡


n/a
 
Extended tcpdump (libpcap) capture file (Linux/Unix)




37 7A BC AF 27 1C
 
7z¼¯'.


7Z
 
7-Zip compressed file




37 E4 53 96 C9 DB D6 07
 
7äS–ÛÖ.


n/a
 
zisofs compression format, recognized by some Linux kernels. See the
libburnia page for additional information.




38 42 50 53
 
8BPS


PSD
 
Photoshop image file




3A 56 45 52 53 49 4F 4E
 
:VERSION


SLE
 
Surfplan kite project file




3C
 
<


ASX
 
Advanced Stream redirector file


XDR
 
BizTalk XML-Data Reduced Schema file


WSF
 
Windows Script Component




3C 21 64 6F 63 74 79 70
 
<!doctyp


DCI
 
AOL HTML mail file




3C 3F
 
<?


WSC
 
Windows Script Component




3C 3F 78 6D 6C 20 76 65
72 73 69 6F 6E 3D
 
<?xml ve
rsion=


MANIFEST
 
Windows Visual Stylesheet XML file




3C 3F 78 6D 6C 20 76 65
72 73 69 6F 6E 3D 22 31
2E 30 22 3F 3E
 
<?xml ve
rsion="1
.0"?>


XUL
 
XML User Interface Language file




3C 3F 78 6D 6C 20 76 65
72 73 69 6F 6E 3D 22 31
2E 30 22 3F 3E 0D 0A 3C
4D 4D 43 5F 43 6F 6E 73
6F 6C 65 46 69 6C 65 20
43 6F 6E 73 6F 6C 65 56
65 72 73 69 6F 6E 3D 22
 
<?xml ve
rsion="1
.0"?>..<
MMC_Cons
oleFile
ConsoleV
ersion="


MSC
 
Microsoft Management Console Snap-in Control file




3C 43 54 72 61 6E 73 54
69 6D 65 6C 69 6E 65 3E
 
<CTransT
imeline>


MXF
 
Picasa movie project file




3C 43 73 6F 75 6E 64 53
79 6E 74 68 65 73 69 7A
 
<CsoundS
ynthesiz


CSD
 
Csound music file




3C 4D 61 6B 65 72 46 69
6C 65 20
 
<MakerFi
le


FM, MIF
 
Adobe FrameMaker file




3C 67 70 78 20 76 65 72
73 69 6F 6E 3D 22 31 2E
31
 
<gpx ver
sion="1.
1


GPX
 
GPS eXchange file (v1.1 schema)




3C 7E 36 3C 5C 25 5F 30
67 53 71 68 3B
 
<~6<\%_0
gSqh;


B85
 
ASCII85 (aka BASE85) encoded file, sometimes used with PostScript and PDF.
Trailer: 7E 3E 0A (~>.)




[24 (0x18) byte offset]
3E 00 03 00 FE FF 09 00
06
 
[24 (0x18) byte offset]
>...þÿ..
.


WB3
 
Quatro Pro for Windows 7.0 Notebook file




3F 5F 03 00
 
?_..


GID
 
Windows Help index file


HLP
 
Windows Help file




[32 (0x20) byte offset]
40 40 40 20 00 00 40 40
40 40
 
[32 (0x20) byte offset]
@@@ ..@@
@@


ENL
 
EndNote Library File




41 43
 
AC


DWG
 
Generic AutoCAD drawing file




NOTES on AutoCAD file headers: The 0x41-43 (AC) is a generic header, occupying the first
two bytes in the file. The next three or four bytes give further indication about the version
(see also DWG file specifications released by OpenDesign):
0x31-2E-32 (1.2) — AutoCAD v1.2 (Release 2)
0x31-2E-33 (1.3) — AutoCAD v1.3 (Release 3)
0x31-2E-34-30 (1.40) — AutoCAD v1.40 (Release 4)
0x31-2E-35-30 (1.50) — AutoCAD v2.05 (Release 5)
0x32-2E-31-30 (2.10) — AutoCAD v2.10 (Release 6)
0x31-30-30-32 (1002) — AutoCAD v2.5 (Release 7)
0x31-30-30-33 (1003) — AutoCAD v2.6 (Release 8)
0x31-30-30-34 (1004) — AutoCAD v9.0 (Release 9)
0x31-30-30-36 (1006) — AutoCAD v10.0 (Release 10)
0x31-30-30-39 (1009) — AutoCAD v11.0 (Release 11)/v12.0 (Release 12)
0x31-30-31-32 (1012) — AutoCAD v13.0 (Release 13)
0x31-30-31-34 (1014) — AutoCAD v14.0 (Release 14)
0x31-30-31-35 (1015) — AutoCAD 2000 (v15.0)/2000i (v15.1)/2002 (v15.2) -- (Releases 15-17)
0x31-30-31-38 (1018) — AutoCAD 2004 (v16.0)/2005 (v16.1)/2006 (v16.2) -- (Releases 18-20)
0x31-30-32-31 (1021) — AutoCAD 2007 (v17.0)/2008 (v17.1)/2009 (v17.2) -- (Releases 21-23)
0x31-30-32-34 (1024) — AutoCAD 2010 (v18.0)/2011 (v18.1)/2012 (v18.2) -- (Releases 24-26)
0x31-30-32-37 (1027) — AutoCAD 2013 (v19.0)/2014 (v19.1)/2015 (v20.0)/2016 (v20.1)/2017 (v20.2) -- (Releases 27-31)
0x31-30-33-32 (1032) — AutoCAD 2018 (v22.0) (Release 32)
41 43 76
 
ACL


SLE
 
Steganos Security Suite virtual secure drive




41 43 53 44
 
ACSD


n/a
 
Miscellaneous AOL parameter and information files




41 45 53
 
AES


AES
 
AES Crypt file format. (The fourth byte is the version number.)




41 4D 59 4F
 
AMYO


SYW
 
Harvard Graphics symbol graphic




41 4F 4C 20 46 65 65 64
62 61 67
 
AOL Feed
bag


BAG
 
AOL and AIM buddy list file




41 4F 4C 44 42
 
AOLDB


ABY, IDX
 
AOL database files: address book (ABY) and user configuration
data (MAIN.IDX)




41 4F 4C 49 44 58
 
AOLIDX


IND
 
AOL client preferences/settings file (MAIN.IND)




41 4F 4C 49 4E 44 45 58
 
AOLINDEX


ABI
 
AOL address book index file




41 4F 4C 56 4D 31 30 30
 
AOLVM100


ORG, PFC
 
AOL personal file cabinet (PFC) file
NOTE: See PFC-Details.zip for PFC file format information.




41 56 47 36 5F 49 6E 74
65 67 72 69 74 79 5F 44
61 74 61 62 61 73 65
 
AVG6_Int
egrity_D
atabase


DAT
 
AVG6 Integrity database file




41 72 43 01
 
ArC.


ARC
 
FreeArc compressed file




42 41 41 44
 
BAAD


n/a
 
NTFS Master File Table (MFT) entry (1,024 bytes)




42 45 47 49 4E 3A 56 43
41 52 44 0D 0A
 
BEGIN:VC
ARD..


VCF
 
vCard file




42 4C 49 32 32 33
 
BLI223


BLI, RBI
 
Thomson Speedtouch series WLAN router firmware




NOTES on BLI/RBI file headers: The signature above is correct for the generic first six bytes.
Reportedly, the 7th & 8th bytes vary by version, and the 9th byte is always 0x30.
v6.0.7.1 (.bli) — 0x42-4C-49-32-32-33-51-4B-30 (BLI223QK0)
v7.4.1.7 (.bli) — 0x42-4C-49-32-32-33-51-48-30 (BLI223QH0)
v8.2.2.5 (.bli) — 0x42-4C-49-32-32-33-55-46-30 (BLI223UF0)
v8.4.3 (.bli/.rbi) — 0x42-4C-49-32-32-33-57-31-30 (BLI223W10)
42 4D
 
BM


BMP, DIB
 
Windows (or device-independent) bitmap image
NOTE: Bytes 2-5 contain the file length in little-endian order.




42 4F 4F 4B 4D 4F 42 49
 
BOOKMOBI


PRC
 
Palmpilot resource file




42 50 47 FB
 
BPG#xFB;


BPG
 
Better Portable Graphics image format




42 5A 68
 
BZh


BZ2, TAR.BZ2, TBZ2, TB2
 
bzip2 compressed archive


DMG
 
Mac Disk image (BZ2 compressed)




42 65 67 69 6E 20 50 75
66 66 65 72 20 44 61 74
61 0D 0A
 
Begin Pu
ffer Dat
a..


APUF
 
Puffer ASCII-armored encrypted archive




42 6C 69 6E 6B 20 62 79
20 44 2E 54 2E 53
 
Blink by
D.T.S


BLI
 
BLINK compressed archive




43 23 2B 44 A4 43 4D A5
48 64 72
 
C#+D¤CM¥
Hdr


RTD
 
RagTime document file




43 41 54 20
 
CAT


IFF
 
Electronic Arts' Interchange Format Files (IFF) format.




43 42 46 49 4C 45
 
CBFILE


CBD
 
WordPerfect dictionary file (unconfirmed)




43 44 30 30 31
 
CD001


ISO
 
ISO-9660 CD Disc Image
This signature usually occurs at byte offset 32769 (0x8001),
34817 (0x8801), or 36865 (0x9001).
More information can be found at MacTech or at ECMA.




43 49 53 4F
 
CISO


CSO
 
Compressed ISO (CISO) CD image




43 4D 4D 4D 15 00 00 00
 
CMMM....


DB
 
Windows 7 thumbcache_sr.db or other thumbcache file
(except thumbcache_idx.db)




43 4D 58 31
 
CMX1


CLB
 
Corel Binary metafile




43 4F 4D 2B
 
COM+


CLB
 
COM+ Catalog file




43 4F 57 44
 
COWD


VMDK
 
VMware 3 Virtual Disk (portion of a split disk) file




43 50 54 37 46 49 4C 45
 
CPT7FILE


CPT
 
Corel Photopaint file




43 50 54 46 49 4C 45
 
CPTFILE


CPT
 
Corel Photopaint file




43 52 45 47
 
CREG


DAT
 
Windows 9x registry hive




43 52 55 53 48 20 76
 
CRUSH v


CRU
 
Crush compressed archive




43 57 53
 
CWS


SWF
 
Macromedia Shockwave Flash player file (zlib compressed, SWF 6 and later).
See SWF File Format Specification.




43 61 6C 63 75 6C 75 78
20 49 6E 64 6F 6F 72 20
 
Calculux
Indoor


CIN
 
Calculux Indoor lighting design software project file




43 61 74 61 6C 6F 67 20
33 2E 30 30 00
 
Catalog
3.00.


CTF
 
WhereIsIt Catalog file




43 6C 69 65 6E 74 20 55
72 6C 43 61 63 68 65 20
4D 4D 46 20 56 65 72 20
 
Client U
rlCache
MMF Ver


DAT
 
Microsoft Internet Explorer cache file (index.dat) file




43 72 32 34
 
Cr24


CRX
 
Google Chrome Extension




43 72 65 61 74 69 76 65
20 56 6F 69 63 65 20 46
 
Creative
Voice F


VOC
 
Creative Voice audio file




44 41 41 00 00 00 00 00
 
DAA.....


DAA
 
PowerISO Direct-Access-Archive image




44 41 58 00
 
DAX.


DAX
 
DAX Compressed CD image




44 42 46 48
 
DBFH


DB
 
Palm Zire photo database




44 4D 53 21
 
DMS!


DMS
 
Amiga DiskMasher compressed archive




44 4F 53
 
DOS


ADF
 
Amiga disk file




44 53 44 20
 
DSD


DSF
 
DSD Storage Facility audio file




44 53 54 62
 
DSTb


DST
 
DST compressed file




44 56 44
 
DVD


DVR
 
DVR-Studio stream file


IFO
 
DVD info file




45 4C 49 54 45 20 43 6F
6D 6D 61 6E 64 65 72 20
 
ELITE Co
mmander


CDR
 
Elite Plus Commander saved game file




45 4E 54 52 59 56 43 44
02 00 00 01 02 00 18 58
 
ENTRYVCD
.......X


VCD
 
VideoVCD (GNU VCDImager) file




45 52 02 00 00
 
CD...


ISO
 
Apple ISO 9660/HFS hybrid CD image




45 52 46 53 53 41 56 45
44 41 54 41 46 49 4C 45
 
ERFSSAVE
DATAFILE


DAT
 
Kroll EasyRecovery Saved Recovery State file




45 50
 
EP


MDI
 
Microsoft Document Imaging file




45 56 46 09 0D 0A FF 00
 
EVF...ÿ.


Enn (where nn are numbers)
 
Expert Witness Compression Format (EWF) file, including EWF-E01
and EWF-S01, as used in EnCase and SMART evidence files. Byte
offset 9 (i.e., byte #10) contains the segment number, starting with 0x01.
See the EWF specification.




45 56 46 32 0D 0A 81
 
EVF2...


Exnn (where nn are numbers)
 
EnCase® Evidence File Format Version 2 (Ex01).
See the EVFv2 specification.




45 6C 66 46 69 6C 65 00
 
ElfFile.


EVTX
 
Windows Vista event log file




45 86 00 00 06 00
 
E†....


QBB
 
Intuit QuickBooks backup file




46 41 58 43 4F 56 45 52
2D 56 45 52
 
FAXCOVER
-VER


CPE
 
Microsoft Fax Cover Sheet




46 44 42 48 00
 
FDBH.


FDB
 
Fiasco database definition file




46 45 44 46
 
FEDF


SBV
 
(Unknown file type)




46 49 4C 45
 
FILE


n/a
 
NTFS Master File Table (MFT) entry (1,024 bytes)




46 4C 56 01
 
FLV.


FLV
 
Flash video file




46 4F 52 4D
 
FORM


ANM
 
IFF ANIM (Amiga delta/RLE encoded bitmap animation) file


IFF
 
Electronic Arts' Interchange Format Files (IFF) format.




46 4F 52 4D 00
 
FORM.


AIFF
 
Audio Interchange File


DAX
 
DAKX Compressed Audio




46 57 53
 
FWS


SWF
 
Macromedia Shockwave Flash player file (uncompressed). See
SWF File Format Specification.




46 72 6F 6D 20 20 20 or
 
From


46 72 6F 6D 20 3F 3F 3F or
 
From ???


46 72 6F 6D 3A 20
 
From:


EML
 
A commmon file extension for e-mail files. Signatures shown here
are for Netscape, Eudora, and a generic signature, respectively.
EML is also used by Outlook Express and QuickMail.




47
 
G


TS, TSA, TSV
 
MPEG transport stream file. (This is not a lot to go on, but MPEG-2 Part 1
Transport (MP2T) files are reportedly broken into 188-byte packets and the
0x47 byte is the sync byte, so should repeat every 188 bytes in the file.)




47 46 31 50 41 54 43 48
 
GF1PATCH


PAT
 
Advanced Gravis Ultrasound patch file




47 49 46 38 37 61 or
 
GIF87a


47 49 46 38 39 61
 
GIF89a


GIF
 
Graphics interchange format file
Trailer: 00 3B (.;)




47 50 41 54
 
GPAT


PAT
 
GIMP (GNU Image Manipulation Program) pattern file




47 52 49 42
 
GRIB


GRB
 
GRIdded Binary or General Regularly-distributed Information in Binary file, commonly used in
meteorology to store historical and forecast weather data




47 58 32
 
GX2


GX2
 
Show Partner graphics file (not confirmed)




47 65 6E 65 74 65 63 20
4F 6D 6E 69 63 61 73 74
 
Genetec
Omnicast


G64
 
Genetec video archive




48 45 41 44 45 52 20 52
45 43 4F 52 44 2A 2A 2A
 
HEADER R
ECORD***


XPT
 
SAS Transport dataset file format




48 48 47 42 31
 
HHGB1


SH3
 
Harvard Graphics presentation file




49 20 49
 
I I


TIF, TIFF
 
Tagged Image File Format file




49 44 33
 
ID3


MP3
 
MPEG-1 Audio Layer 3 (MP3) audio file




49 44 33 03 00 00 00
 
ID3....


KOZ
 
Sprint Music Store audio file (for mobile devices)




49 49 1A 00 00 00 48 45
41 50 43 43 44 52 02 00
 
II....HE
APCCDR..


CRW
 
Canon digital camera RAW file




49 49 2A 00
 
II*.


TIF, TIFF
 
Tagged Image File Format file (little
endian, i.e., LSB first in the byte; Intel)




49 49 2A 00 10 00 00 00
43 52
 
II*.....
CR


CR2
 
Canon digital camera RAW file




49 4D 4D 4D 15 00 00 00
 
IMMM....


DB
 
Windows 7 thumbcache_idx.db file




49 53 63 28
 
ISc(


CAB, HDR
 
Install Shield v5.x or 6.x compressed file




49 54 4F 4C 49 54 4C 53
 
ITOLITLS


LIT
 
Microsoft Reader eBook file




49 54 53 46
 
ITSF


CHI, CHM
 
Microsoft Compiled HTML Help File




49 6E 6E 6F 20 53 65 74
75 70 20 55 6E 69 6E 73
74 61 6C 6C 20 4C 6F 67
20 28 62 29
 
Inno Set
up Unins
tall Log
 (b)


DAT
 
Inno Setup Uninstall Log file




49 6E 74 65 72 40 63 74
69 76 65 20 50 61 67 65
 
Inter@ct
ive Page


IPD
 
Inter@ctive Pager Backup (BlackBerry) backup file
(See also this IPD File Format paper)




4A 41 52 43 53 00
 
JARCS.


JAR
 
JARCS compressed archive




4A 47 03 0E or
 
JG..


4A 47 04 0E
 
JG..


ART
 
AOL ART file
Trailers:
For 0x4A-47-03-0E: D0 CB 00 00 (ÐË..)
For 0x4A-47-04-0E: CF C7 CB (ÏÇË)




4B 44 4D
 
KDM


VMDK
 
VMware 4 Virtual Disk (portion of a split disk) file




4B 44 4D 56
 
KDMV


VMDK
 
VMware 4 Virtual Disk (monolitic disk) file




4B 47 42 5F 61 72 63 68
20 2D
 
KGB_arch
 -


KGB
 
KGB archive




4B 49 00 00
 
KI..


SHD
 
Windows 9x printer spool file




4B 57 41 4A 88 F0 27 D1
 
KWAJˆð'Ñ


n/a
 
KWAJ file format used by DOS COMPRESS.EXE and EXPAND.EXE commands.
This command compresses a single file, replacing the last character in the file name
with an underscore or dollar sign, e.g., FOO.BAZ would be renamed FOO.BA_ or
FOO.BA$. (See the SZDD/KWAJ page for more information.)




4C 00 00 00 01 14 02 00
 
L.......


LNK
 
Windows shell link (shortcut) file. See also The Meaning of Linkfiles in Forensic Examinations
and Evidentiary Value of Link Files.




4C 01
 
L.


OBJ
 
Microsoft Common Object File Format (COFF) relocatable
object code file for an Intel 386 or later/compatible processors




4C 41 3A
 
LA:


DST
 
Tajima embroidery sticj image file




4C 49 53 54
 
LIST


IFF
 
Electronic Arts' Interchange Format Files (IFF) format.




4C 50 46 20 00 01
 
LPF ..


ANM
 
DeluxePaint Animation file




4C 4E 02 00
 
LN..


GID
 
Windows Help index file


HLP
 
Windows Help file




4C 56 46 09 0D 0A FF 00
 
LVF...ÿ.


Enn (where nn are numbers)
 
Logical File Evidence Format (EWF-L01) as used in later versions of
EnCase evidence files. See the EWF specification.




4D 2D 57 20 50 6F 63 6B
65 74 20 44 69 63 74 69
 
M-W Pock
et Dicti


PDB
 
Merriam-Webster Pocket Dictionary file




4D 41 52 31 00
 
MAR1.


MAR
 
Mozilla archive




4D 41 52 43
 
MARC


MAR
 
Microsoft/MSN MARC archive




4D 41 54 4C 41 42 20 35
2E 30 20 4D 41 54 2D 66
69 6C 65
 
MATLAB 5
.0 MAT-f
ile


MAT
 
MATLAB v5 workspace file (includes creation timestamp)




4D 41 72 30 00
 
MAr0.


MAR
 
MAr compressed archive




4D 43 57 20 54 65 63 68
6E 6F 67 6F 6C 69 65 73
 
MCW Tech
nogolies


MTE
 
TargetExpress target file




4D 44 4D 50 93 A7
 
MDMP“§


HDMP
 
Windows heap dump file


DMP
 
Windows minidump file




4D 49 4C 45 53
 
MILES


MLS
 
Milestones v1.0 project management and scheduling software
(Also see "MV2C" and "MV214" signatures)




4D 4C 53 57
 
MLSW


MLS
 
Skype localization data file




4D 4D 00 2A
 
MM.*


TIF, TIFF
 
Tagged Image File Format file (big
endian, i.e., LSB last in the byte; Motorola)




4D 4D 00 2B
 
MM.+


TIF, TIFF
 
BigTIFF files; Tagged Image File Format files >4 GB




4D 4D 4D 44 00 00
 
MMMD..


MMF
 
Yamaha Corp. Synthetic music Mobile Application Format (SMAF)
for multimedia files that can be played on hand-held devices.




4D 52 56 4E
 
MRVN


NVRAM
 
VMware BIOS (non-volatile RAM) state file




4D 53 43 46
 
MSCF


CAB
 
Microsoft cabinet file


ONEPKG
 
OneNote Package file


PPZ
 
Powerpoint Packaged Presentation


SNP
 
Microsoft Access Snapshot Viewer file




4D 53 46 54 02 00 01 00
 
MSFT....


TLB
 
OLE, SPSS, or Visual C++ type library file




4D 53 57 49 4D
 
MSWIM


WIM
 
Microsoft Windows Imaging Format file




4D 53 5F 56 4F 49 43 45
 
MS_VOICE


CDR, DVF
 
Sony Compressed Voice File


MSV
 
Sony Memory Stick Compressed Voice file




4D 54 68 64
 
MThd


MID, MIDI
 
Musical Instrument Digital Interface (MIDI) sound file


PCS
 
Yamaha Piano sound file




4D 56
 
MV


DSN
 
CD Stomper Pro label file




4D 56 32 31 34
 
MV214


MLS
 
Milestones v2.1b project management and scheduling software
(Also see "MILES" and "MV2C" signatures)




4D 56 32 43
 
MV2C


MLS
 
Milestones v2.1a project management and scheduling software
(Also see "MILES" and "MV214" signatures)




4D 5A
 
MZ


COM, DLL, DRV, EXE, PIF, QTS, QTX, SYS
 
Windows/DOS executable file
(See The MZ EXE File Format page for the structure of an EXE file,
with coverage of NE, TLINK, PE, self-extracting archives, and more.)
Note: MZ are the initals of Mark Zbikowski, designer of the DOS executable file format.


ACM
 
MS audio compression manager driver


AX
 
Library cache file


CPL
 
Control panel application


FON
 
Font file


OCX
 
ActiveX or OLE Custom Control


OLB
 
OLE object library


SCR
 
Screen saver


VBX
 
VisualBASIC application


VXD, 386
 
Windows virtual device drivers




4D 5A 90 00 03 00 00 00
 
MZ......


API
 
Acrobat plug-in


AX
 
DirectShow filter


FLT
 
Audition graphic filter file (Adobe)




4D 5A 90 00 03 00 00 00
04 00 00 00 FF FF
 
MZ......
....ÿÿ


ZAP
 
ZoneAlam data file




4D 69 63 72 6F 73 6F 66
74 20 43 2F 43 2B 2B 20
 
Microsof
t C/C++


PDB
 
Microsoft C++ debugging symbols file




4D 69 63 72 6F 73 6F 66
74 20 56 69 73 75 61 6C
20 53 74 75 64 69 6F 20
53 6F 6C 75 74 69 6F 6E
20 46 69 6C 65
 
Microsof
t Visual
 Studio
Solution
 File


SLN
 
Visual Studio .NET Solution file




[84 (0x54) byte offset]
4D 69 63 72 6F 73 6F 66
74 20 57 69 6E 64 6F 77
73 20 4D 65 64 69 61 20
50 6C 61 79 65 72 20 2D
2D 20
 
[84 (0x54) byte offset]
Microsof
t Window
s Media
Player -
-


WPL
 
Windows Media Player playlist




4D 73 52 63 66
 
MsRcf


GDB
 
VMapSource GPS Waypoint Database




4E 41 56 54 52 41 46 46
49 43
 
NAVTRAFF
IC


DAT
 
TomTom traffic data file




4E 42 2A 00
 
NB*.


JNT, JTP
 
MS Windows journal file




4E 45 53 4D 1A 01
 
NESM..


NSF
 
NES Sound file




4E 49 54 46 30
 
NITF0


NTF
 
National Imagery Transmission Format (NITF) file




4E 61 6D 65 3A 20
 
Name:


COD
 
Agent newsreader character map file




4F 50 43 4C 44 41 54
 
OPCLDAT


attachment
 
1Password 4 Cloud Keychain encrypted attachment




4F 50 4C 44 61 74 61 62
61 73 65 46 69 6C 65
 
OPLDatab
aseFile


DBF
 
Psion Series 3 Database file




4F 54 54 4F 00
 
OTTO.


OTF
 
OpenType font file




4F 67 67 53 00 02 00 00
00 00 00 00 00 00
 
OggS....
......


OGA, OGG, OGV, OGX
 
Ogg Vorbis Codec compressed Multimedia file




4F 7B
 
O{


DW4
 
Visio/DisplayWrite 4 text file (unconfirmed)




50 00 00 00 20 00 00 00
 
P... ...


IDX
 
Quicken QuickFinder Information File




50 35 0A
 
P5.


PGM
 
Portable Graymap Graphic




50 41 43 4B
 
PACK


PAK
 
Quake archive file




50 41 47 45 44 55 36 34
 
PAGEDU64


DMP
 
Windows 64-bit memory dump




50 41 47 45 44 55 4D 50
 
PAGEDUMP


DMP
 
Windows memory dump




50 41 58
 
PAX


PAX
 
PAX password protected bitmap




50 45 53 54
 
PEST


DAT
 
PestPatrol data/scan strings




50 47 50 64 4D 41 49 4E
 
PGPdMAIN


PGD
 
PGP disk image




50 49 43 54 00 08
 
PICT..


IMG
 
ADEX Corp. ChromaGraph Graphics Card Bitmap Graphic file




50 4B 03 04
 
PK..


ZIP
 
PKZIP archive file (Ref. 1 | Ref. 2)
Trailer: filename 50 4B 17 characters 00 00 00
Trailer: (filename PK 17 characters ...)
Note: PK are the initals of Phil Katz, co-creator of the ZIP file format and author of PKZIP.


ZIP
 
Apple Mac OS X Dashboard Widget, Aston Shell theme, Oolite eXpansion Pack,
Opera Widget, Pivot Style Template, Rockbox Theme package, Simple Machines
Forums theme, SubEthaEdit Mode, Trillian zipped skin, Virtual Skipper skin


APK
 
Android package


JAR
 
Java archive; compressed file package for classes and data


KMZ
 
Google Earth saved working session file


KWD
 
KWord document


ODT, ODP, OTT
 
OpenDocument text document, presentation, and text document template, respectively.


OXPS
 
Microsoft Open XML paper specification file


SXC, SXD, SXI, SXW
 
OpenOffice spreadsheet (Calc), drawing (Draw), presentation (Impress),
and word processing (Writer) files, respectively.


SXC
 
StarOffice spreadsheet


WMZ
 
Windows Media compressed skin file


XPI
 
Mozilla Browser Archive


XPS
 
XML paper specification file


XPT
 
eXact Packager Models




50 4B 03 04 0A 00 02 00
 
PK......


EPUB
 
Open Publication Structure eBook file. (Should also include the string:
mimetypeapplication/epub+zip)




50 4B 03 04 14 00 01 00
63 00 00 00 00 00
 
PK......
c.....


ZIP
 
ZLock Pro encrypted ZIP




50 4B 03 04 14 00 06 00
 
PK......


DOCX, PPTX, XLSX
 
Microsoft Office Open XML Format (OOXML) Document
NOTE: There is no subheader for MS OOXML files as there is with
DOC, PPT, and XLS files. To better understand the format of these files,
rename any OOXML file to have a .ZIP extension and then unZIP the file;
look at the resultant file named [Content_Types].xml to see the content
types. In particular, look for the <Override PartName= tag, where you
will find word, ppt, or xl, respectively.

Trailer: Look for 50 4B 05 06 (PK..) followed by 18 additional bytes
at the end of the file.




50 4B 03 04 14 00 08 00
08 00
 
PK......
..


JAR
 
Java archive




50 4B 05 06
 
PK..


ZIP
 
PKZIP empty archive file




50 4B 07 08
 
PK..


ZIP
 
PKZIP multivolume archive file




[30 (0x1E) byte offset]
50 4B 4C 49 54 45
 
[30 (0x1E) byte offset]
PKLITE


ZIP
 
PKLITE compressed ZIP archive (see also PKZIP)




[526 (0x20E) byte offset]
50 4B 53 70 58
 
[526 (0x20E) byte offset]
PKSFX


ZIP
 
PKSFX self-extracting executable compressed file (see also PKZIP)




50 4D 43 43
 
PMCC


GRP
 
Windows Program Manager group file




50 4E 43 49 55 4E 44 4F
 
PNCIUNDO


DAT
 
Norton Disk Doctor undo file




50 4D 4F 43 43 4D 4F 43
 
PMOCCMOC


DAT
 
Microsoft® Windows® User State Migration Tool (USMT). USMT 3.0
applies to Windows XP and Windows Vista®, and USMT 4.0 is for Windows 7.




50 53 46 12
 
PSF.


DSF
 
Dreamcast Sound Format file, a subset of the Portable Sound Format.




50 55 46 58
 
PUFX


PUF
 
Puffer encrypted archive




50 61 56 45
 
PaVE


n/a
 
Parrot Video Encapsulation file




[92 (0x5C) byte offset]
51 45 4C 20
 
[92 (0x5C) byte offset]
QEL


QEL
 
Quicken data file




51 46 49 FB
 
QFIû


IMG
 
QEMU Qcow Disk Image




51 57 20 56 65 72 2E 20
 
QW Ver.


ABD, QSD
 
Quicken data file




[512 (0x200) byte offset]
52 00 6F 00 6F 00 74 00
20 00 45 00 6E 00 74 00
72 00 79 00
 
[512 (0x200) byte offset]
R.o.o.t.
.E.n.t.
r.y.


MSG
 
Outlook/Exchange message subheader (MS Office)




52 41 5A 41 54 44 42 31
 
RAZATDB1


DAT
 
Shareaza (Windows P2P client) thumbnail




52 44 58 32 0A
 
RDX2.


RDATA
 
R (programming language) saved work space




52 45 47 45 44 49 54
 
REGEDIT


REG, SUD
 
Windows NT Registry and Registry Undo files




52 45 56 4E 55 4D 3A 2C
 
REVNUM:,


ADF
 
Antenna data file




52 49 46 46
 
RIFF


ANI
 
Windows animated cursor


CMX
 
Corel Presentation Exchange (Corel 10 CMX) Metafile


CDR
 
CorelDraw document


DAT
 
Video CD MPEG or MPEG1 movie file




DS4
 
Micrografx Designer v4 graphic file


4XM
 
4X Movie video




52 49 46 46 xx xx xx xx
41 56 49 20 4C 49 53 54
 
RIFF....
AVI LIST


AVI
 
Resource Interchange File Format -- Windows Audio Video
Interleave file, where xx xx xx xx is the file size (little endian)




52 49 46 46 xx xx xx xx
43 44 44 41 66 6D 74 20
 
RIFF....
CDDAfmt


CDA
 
Resource Interchange File Format -- Compact Disc Digital
Audio (CD-DA) file, where xx xx xx xx is the file size (little endian)




52 49 46 46 xx xx xx xx
51 4C 43 4D 66 6D 74 20
 
RIFF....
QLCMfmt


QCP
 
Resource Interchange File Format -- Qualcomm
PureVoice, where xx xx xx xx is the file size (little endian)




52 49 46 46 xx xx xx xx
52 4D 49 44 64 61 74 61
 
RIFF....
RMIDdata


RMI
 
Resource Interchange File Format -- Windows Musical
Instrument Digital Interface file, where xx xx xx xx is the file
size (little endian)




52 49 46 46 xx xx xx xx
57 41 56 45 66 6D 74 20
 
RIFF....
WAVEfmt


WAV
 
Resource Interchange File Format -- Audio for Windows
file, where xx xx xx xx is the file size (little endian)




52 49 46 46 xx xx xx xx
57 45 42 50
 
RIFF....
WEBP


WEBP
 
Google WebP image file, where xx xx xx xx is the file size




52 54 53 53
 
RTSS


CAP
 
Windows NT Netmon capture file




52 61 72 21 1A 07 00
 
Rar!...


RAR
 
RAR (v4.x) compressed archive file




52 61 72 21 1A 07 01 00
 
Rar!....


RAR
 
RAR (v5) compressed archive file




52 65 74 75 72 6E 2D 50
61 74 68 3A 20
 
Return-P
ath:


EML
 
A commmon file header for e-mail files.




[4 byte offset]
53 43 43 41
 
[4 byte offset]
SCCA


PF
 
Windows prefetch file. The first four bytes indicate the OS:
0x11-00-00-00 = XP, 0x17-00-00-00 = Vista/Win7,
and 0x1A-00-00-00 = Win8.1 (and probably Win8, as well).




53 43 48 6C
 
SCHl


AST
 
Need for Speed: Underground Audio file




53 43 4D 49
 
SCMI


IMG
 
Img Software Set Bitmap




53 44 50 58
 
SDPX


DPX
 
Society of Motion Picture and Television Engineers (SMPTE)
Digital Picture Exchange (DPX) image file (big endian)




53 48 4F 57
 
SHOW


SHW
 
Harvard Graphics DOS Ver. 2/x Presentation file




53 49 45 54 52 4F 4E 49
43 53 20 58 52 44 20 53
43 41 4E
 
SIETRONI
CS XRD S
CAN


CPI
 
Sietronics CPI XRD document




53 49 4D 50 4C 45 20 20
3D 20 20 20 20 20 20 20
20 20 20 20 20 20 20 20
20 20 20 20 20 54
 
SIMPLE
=

     T


FITS
 
Flexible Image Transport System (FITS), Version 3.0 file




53 49 54 21 00
 
SIT!.


SIT
 
StuffIt compressed archive




53 4D 41 52 54 44 52 57
 
SMARTDRW


SDR
 
SmartDraw Drawing file




53 50 46 49 00
 
SPFI.


SPF
 
StorageCraft ShadownProtect backup file




53 50 56 42
 
SPVB


SPVCHAIN
 
MultiBit Bitcoin blockchain file




53 51 4C 4F 43 4F 4E 56
48 44 00 00 31 2E 30 00
 
SQLOCONV
HD..1.0.


CNV
 
DB2 conversion file




53 51 4C 69 74 65 20 66
6F 72 6D 61 74 20 33 00
 
SQLite f
ormat 3.


DB
 
SQLite database file




53 5A 20 88 F0 27 33 D1
 
SZ ˆð'3Ñ


n/a
 
QBASIC SZDD file header variant. (See the SZDD or KWAJ format entries
for additional information.)




53 5A 44 44 88 F0 27 33
 
SZDDˆð'3


n/a
 
SZDD file format used by DOS COMPRESS.EXE and EXPAND.EXE commands.
This command compresses a single file, replacing the last character in the file name
with an underscore or dollar sign, e.g., FOO.BAZ would be renamed FOO.BA_ or
FOO.BA$. (See the SZDD/KWAJ page for more information.)




53 6D 62 6C
 
Smbl


SYM
 
(Unconfirmed file type. Likely type is Harvard Graphics
Version 2.x graphic symbol or Windows SDK graphic symbol)




53 74 75 66 66 49 74 20
28 63 29 31 39 39 37 2D
 
StuffIt
(c)1997-


SIT
 
StuffIt compressed archive




53 75 70 65 72 43 61 6C
63
 
SuperCal
c


CAL
 
SuperCalc worksheet




54 48 50 00
 
THP.


THP
 
Wii/GameCube video file




54 68 69 73 20 69 73 20
 
This is


INFO
 
UNIX GNU Info Reader File




55 43 45 58
 
UCEX


UCE
 
Unicode extensions




55 46 41 C6 D2 C1
 
UFAÆÒÁ


UFA
 
UFA compressed archive




55 46 4F 4F 72 62 69 74
 
UFOOrbit


DAT
 
UFO Capture v2 map file




56 43 50 43 48 30
 
VCPCH0


PCH
 
Visual C PreCompiled header file




56 45 52 53 49 4F 4E 20
 
VERSION


CTL
 
Visual Basic User-defined Control file




56 65 72 73 69 6F 6E 20
 
Version


MIF
 
MapInfo Interchange Format file




57 04 00 00 53 50 53 53
20 74 65 6D 70 6C 61 74
 
W...SPSS
templat


SCT
 
SPSS Statistics (née Statistical Package for the Social Sciences, then
Statistical Product and Service Solutions) template file




57 4D 4D 50
 
WMMP


DAT
 
Walkman MP3 container file




57 53 32 30 30 30
 
WS2000


WS2
 
WordStar for Windows Ver. 2 document




[29,152 (0x71E0) byte offset]
57 69 6E 5A 69 70
 
[29,152 (0x71E0) byte offset]
WinZip


ZIP
 
WinZip compressed archive




57 6F 72 64 50 72 6F
 
WordPro


LWP
 
Lotus WordPro document.




58 2D
 
X-


EML
 
A commmon file extension for e-mail files. This variant is
for Exchange.




58 43 50 00
 
XCP.


CAP
 
Cinco NetXRay, Network General Sniffer, and
Network Associates Sniffer capture file




58 50 43 4F 4D 0A 54 79
70 65 4C 69 62
 
XPCOM.Ty
peLib


XPT
 
XPCOM type libraries for the XPIDL compiler




58 50 44 53
 
XPDS


DPX
 
Society of Motion Picture and Television Engineers (SMPTE)
Digital Picture Exchange (DPX) image file (little endian)




58 54
 
XT..


BDR
 
MS Publisher border




5A 4F 4F 20
 
ZOO


ZOO
 
ZOO compressed archive




5A 57 53
 
ZWS


SWF
 
Macromedia Shockwave Flash player file (LZMA compressed, SWF 13 and later).
See SWF File Format Specification.




5B 47 65 6E 65 72 61 6C
5D 0D 0A 44 69 73 70 6C
61 79 20 4E 61 6D 65 3D
3C 44 69 73 70 6C 61 79
4E 61 6D 65
 
[General
]..Displ
ay Name=
<Display
Name


ECF
 
MS Exchange 2007 extended configuration file




5B 4D 53 56 43
 
[MSVC


VCW
 
Microsoft Visual C++ Workbench Information File




5B 50 68 6F 6E 65 5D
 
[Phone]


DUN
 
Dial-up networking file




5B 56 45 52 5D or
 
[VER]


5B 76 65 72 5D or
 
[ver]


SAM
 
Lotus AMI Pro document




5B 56 4D 44 5D or
 
[VMD]


VMD
 
VocalTec VoIP media file




[2 byte offset]
5B 56 65 72 73 69 6F 6E
 
[2 byte offset]
[Version


CIF
 
(Unknown file type)




5B 57 69 6E 64 6F 77 73
20 4C 61 74 69 6E 20
 
[Windows
 Latin


CPX
 
Microsoft Code Page Translation file




5B 66 6C 74 73 69 6D 2E
30 5D
 
[fltsim.
0]


CFG
 
Flight Simulator Aircraft Configuration file




5B 70 6C 61 79 6C 69 73
74 5D
 
[playlis
t]


PLS
 
WinAmp Playlist file




5D FC C8 00
 
]üÈ.


HUS
 
Husqvarna Designer I Embroidery Machine file




5F 27 A8 89
 
_'¨‰


JAR
 
Jar archive




5F 43 41 53 45 5F
 
_CASE_


CAS, CBK
 
EnCase case file (and backup)




60 EA
 
`ê


ARJ
 
Compressed archive file




62 65 67 69 6E
 
begin


n/a
 
UUencoded files start with a string:
  begin mode path
where mode is the set of permissions as used in
Linux/Unix and path is the name given to the decoded
file. (See this uuencode page for more information.)




62 65 67 69 6E 2D 62 61
73 65 36 34
 
begin-ba
se64


b64
 
UUencoded BASE64 file
Trailer: 0A 3D 3D 3D 3D 0A (.====.)




62 70 6C 69 73 74
 
bplist


plist
 
Binary property list (plist)
(NOTE: Next two bytes are the version number, currently
0x30-30, or "00")




63 61 66 66
 
caff


CAF
 
Apple Core Audio File




63 64 73 61 65 6E 63 72
 
cdsaencr


DMG
 
Macintosh encrypted Disk image (v1)




63 6F 6E 65 63 74 69 78
 
conectix


VHD
 
Virtual PC Virtual HD image




63 75 73 68 00 00 00 02
00 00 00
 
cush....
...


CSH
 
Photoshop Custom Shape




64 00 00 00
 
d...


P10
 
Intel PROset/Wireless Profile




64 38 3A 61 6E 6E 6F 75
6E 63 65
 
d8:annou
nce


TORRENT
 
Torrent file




64 65 78 0A
 
dex.


dex
 
Dalvik executable file (Android)




64 6E 73 2E
 
dns.


AU
 
Audacity audio file




64 73 77 66 69 6C 65
 
dswfile


DSW
 
Microsoft Visual Studio workspace file




65 6E 63 72 63 64 73 61
 
encrcdsa


DMG
 
Macintosh encrypted Disk image (v2)




66 49 00 00
 
fI..


SHD
 
Windows NT printer spool file




66 4C 61 43 00 00 00 22
 
fLaC..."


FLAC
 
Free Lossless Audio Codec file




[4 byte offset]
66 74 79 70 33 67 70
 
[4 byte offset]
ftyp3gp


3GG, 3GP, 3G2
 
3rd Generation Partnership Project 3GPP multimedia files




[4 byte offset]
66 74 79 70 4D 34 41 20
 
[4 byte offset]
ftypM4A


M4A
 
Apple Lossless Audio Codec file




[4 byte offset]
66 74 79 70 4D 34 56 20
 
[4 byte offset]
ftypM4V


FLV, M4V
 
ISO Media, MPEG v4 system, or iTunes AVC-LC file




[4 byte offset]
66 74 79 70 4D 53 4E 56
 
[4 byte offset]
ftypMSNV


MP4
 
MPEG-4 video file




[4 byte offset]
66 74 79 70 69 73 6F 6D
 
[4 byte offset]
ftypisom


MP4
 
ISO Base Media file (MPEG-4) v1




[4 byte offset]
66 74 79 70 6D 70 34 32
 
[4 byte offset]
ftypmp42


M4V
 
MPEG-4 video|QuickTime file




[4 byte offset]
66 74 79 70 71 74 20 20
 
[4 byte offset]
ftypqt


MOV
 
QuickTime movie file




67 49 00 00
 
gI..


SHD
 
Windows 2000/XP printer spool file




67 69 6d 70 20 78 63 66
20
 
gimp xcf



XCF
 
GNU Image Manipulation Program (GIMP) eXperimental Computing Facility (XCF)
image file




68 49 00 00
 
hI..


SHD
 
Windows Server 2003 printer spool file




6C 33 33 6C
 
l33l


DBB
 
Skype user data file (profile and contacts)




[4 byte offset]
6D 6F 6F 76
 
[4 byte offset]
moov


MOV
 
QuickTime movie file




.MOV files have a complicated file signature. The string "moov" is the most common but I have also seen:
  0x66-72-65-65   free
  0x6D-64-61-74   mdat
  0x77-69-64-65   wide

And the following have been reported to me:
  0x70-6E-6F-74   pnot
  0x73-6B-69-70   skip

Furthermore, if you look at byte position xxxxxxxx+4 (where xxxxxxxx is bytes 0-3 of the header), you
will find one (or more!) of these strings repeated; the string "free" seems to be the most common. For
more information, see the QuickTime File Format page. (Thanks to D. Wright for getting me started on this!)




6D 73 46 69 6C 74 65 72
4C 69 73 74
 
msFilter
List


TPL
 
Internet Explorer v11 Tracking Protection List file




6D 75 6C 74 69 42 69 74
2E 69 6E 66 6F
 
multiBit
.info


INFO
 
MultiBit Bitcoin wallet information file




6F 3C
 
o<


n/a
 
Short Message Service (SMS), or text, message stored on a
Subscriber Identification Module (SIM).




6F 70 64 61 74 61 30 31
 
opdata01


n/a
 
1Password 4 Cloud Keychain encrypted data




72 65 67 66
 
regf


DAT
 
Windows NT registry hive file




72 69 66 66
 
riff


ACD
 
Sonic Foundry Acid Music File (Sony)




72 74 73 70 3A 2F 2F
 
rtsp://


RAM
 
RealMedia metafile




73 6C 68 21 or
 
slh!


DAT
 
Allegro Generic Packfile Data file (compressed)




73 6C 68 2E
 
slh.


DAT
 
Allegro Generic Packfile Data file (uncompressed)




73 6D 5F
 
sm_


PDB
 
PalmOS SuperMemo file




73 6F 6C 69 64
 
solid


STL
 
ASCII STL (STereoLithography) file for 3D printing.




73 72 63 64 6F 63 69 64
3A
 
srcdocid
:


CAL
 
CALS raster bitmap file




73 7A 65 7A
 
szez


PDB
 
PowerBASIC Debugger Symbols file




[60 (0x3C) byte offset]
74 42 4D 50 4B 6E 57 72
 
[60 (0x3C) byte offset]
tBMPKnWr


PRC
 
PathWay Map file, used with GPS devices




74 72 75 65 00
 
true.


TTF
 
TrueType font file




[257 (0x101) byte offset]
75 73 74 61 72
 
[257 (0x101) byte offset]
ustar


TAR
 
Tape Archive file (http://www.mkssoftware.com/docs/man4/tar.4.asp)




76 2F 31 01
 
v/1.


EXR
 
OpenEXR bitmap image format




76 32 30 30 33 2E 31 30
0D 0A 30 0D 0A
 
v2003.10
..0..


FLT
 
Qimage filter




78 01 73 0D 62 62 60
 
x.s.bb`


DMG
 
Mac OS X Disk Copy Disk Image file




78 61 72 21
 
xar!


XAR
 
eXtensible ARchive file




7A 62 65 78
 
zbex


INFO
 
ZoomBrowser Image Index file (ZbThumbnal.info)




7B 0D 0A 6F 20
 
{..o


LGC, LGD
 
Windows application log




7B 5C 70 77 69
 
{\pwi


PWI
 
Microsoft Windows Mobile personal note file




7B 5C 72 74 66
 
{\rtf


RTF
 
Rich text format word processing file
Trailer: 7D (})




7C 4B C3 74 E1 C8 53 A4
79 B9 01 1D FC 4F DD 13
 
|KÃtáÈS¤
y¹..üOÝ.


CSD
 
Huskygram, Poem, or Singer embroidery design file




7E 42 4B 00
 
~BK.


PSP
 
Corel Paint Shop Pro image file




7E 45 53 44 77 F6 85 3E
BF 6A D2 11 45 61 73 79
20 53 74 72 65 65 74 20
44 72 61 77
 
~ESDwö…>
¿jÒ.Easy
 Street
Draw


ESD
 
Easy Street Draw diagram file




7E 74 2C 01 50 70 02 4D
52 01 00 00 00 08 00 00
00 01 00 00 31 00 00 00
31 00 00 00 43 01 FF 00
01 00 08 00 01 00 00 00
7e 74 2c 01
 
~t,.Pp.M
R.......
....1...
1...C.ÿ.
........
~t,.


IMG
 
Reportedly a proprietary recording system, possibly a
Digital Watchdog DW-TP-500G unit.




7F 45 4C 46
 
.ELF


n/a
 
Executable and Linking Format executable file (Linux/Unix)




80
 
.


OBJ
 
Relocatable object code




80 00
 
..


ADX
 
ADX lossy compressed audio file




80 2A 5F D7
 
.*_.


CIN
 
Kodak Cineon image file




81 32 84 C1 85 05 D0 11
B2 90 00 AA 00 3C F6 76
 
.2„Á….Ð.
²..ª.<öv


WAB
 
Outlook Express address book (Win95)




81 CD AB
 
.Í«


WPF
 
WordPerfect text file




86 DD 6x
 
†Ý{lower_case letter}


n/a
 
Possibly, maybe, might be a fragment of an Ethernet frame carrying
an IPv6 packet. See Hints About Looking for Network Packet Fragments.




89 50 4E 47 0D 0A 1A 0A
 
‰PNG....


PNG
 
Portable Network Graphics file
Trailer: 49 45 4E 44 AE 42 60 82 (IEND®B`‚...)




8A 01 09 00 00 00 E1 08
00 00 99 19
 
Š.....á.
..™.


AW
 
MS Answer Wizard file




91 33 48 46
 
‘3HF


HAP
 
Hamarsoft HAP 3.x compressed archive




95 00 or
 
•.


95 01
 
•.


SKR
 
PGP secret keyring file




97 4A 42 32 0D 0A 1A 0A
 
—JB2....


JB2
 
JBOG2 image file
Trailer: 03 33 00 01 00 00 00 00 (.3......)




99
 
™


GPG
 
GNU Privacy Guard (GPG) public keyring




99 01
 
™.


PKR
 
PGP public keyring file




9C CB CB 8D 13 75 D2 11
91 58 00 C0 4F 79 56 A4
 
œËË..UÒ.
‘X.ÀOyV¤


WAB
 
Outlook address file




[512 (0x200) byte offset]
A0 46 1D F0
 
[512 (0x200) byte offset]
 F.ð


PPT
 
PowerPoint presentation subheader (MS Office)




A1 B2 C3 D4
 
¡²ÃÔ


n/a
 
tcpdump (libpcap) capture file (Linux/Unix)




A1 B2 CD 34
 
¡²Í4


n/a
 
Extended tcpdump (libpcap) capture file (Linux/Unix)




A9 0D 00 00 00 00 00 00
 
©.......


DAT
 
Access Data FTK evidence file




AC 9E BD 8F 00 00
 
¬.½...


QDF
 
Quicken data file




AC ED
 
¬í


n/a
 
Java serialization data (see Object Serialization Stream Protocol)




AC ED 00 05 73 72 00 12
62 67 62 6C 69 74 7A 2E
 
¬í..sr..
bgblitz.


PDB
 
BGBlitz (professional Backgammon software) position database file




B0 4D 46 43
 
°MFC


PWL
 
Windows 95 password file




B1 68 DE 3A
 
±hÞ:


DCX
 
Graphics Multipage PCX bitmap file




B4 6E 68 44
 
´nhd


TIB
 
Acronis True Image file (early versions)




B5 A2 B0 B3 B3 B0 A5 B5
 
µ¢°³³°¥µ


CAL
 
Windows calendar file




B8 C9 0C 00
 
¸É..


INS
 
InstallShield Script




BE 00 00 00 AB 00 00 00
00 00 00 00 00
 
¾...«...
....


WRI
 
MS Write file




BE BA FE CA 0F 50 61 6C
6D 53 47 20 44 61 74 61
 
¾ºþÊ.Pal
mSG Data


DAT
 
Palm Desktop DateBook file




C3 AB CD AB
 
Ã«Í«


ACS
 
MS Agent Character file




C5 D0 D3 C6
 
ÅÐÓÆ


EPS
 
Adobe encapsulated PostScript file




C8 00 79 00
 
È.y.


LBK
 
Jeppesen FliteLog file




CA FE BA BE
 
Êþº¾


CLASS
 
Java bytecode file (also used by Apple iOS apps)




CD 20 AA AA 02 00 00 00
 
Í ªª....


n/a
 
Norton Anti-Virus quarantined virus file




CE 24 B9 A2 20 00 00 00
 
Î$¹¢ ...


TIB
 
Acronis True Image file (current versions)




CE CE CE CE
 
ÎÎÎÎ


JCEKS
 
Java Cryptography Extension keystore file




CE FA ED FE
 
Îúíþ


n/a
 
Apple OS X ABI Mach-O binary file (32-bit, where target system has reverse byte
ordering from host running compiler)




CF 11 E0 A1 B1 1A E1 00
 
Ï.à¡±.á.


DOC
 
Perfect Office document
[Note similarity to MS Office header, below]




CF AD 12 FE
 
Ï­.þ


DBX
 
Outlook Express e-mail folder




CF FA ED FE
 
Ïúíþ


n/a
 
Apple OS X ABI Mach-O binary file (64-bit, where target system has reverse byte
ordering from host running compiler)




D0 CF 11 E0 A1 B1 1A E1
 
ÐÏ.à¡±.á


DOC, DOT, PPS, PPT, XLA, XLS, WIZ
 
An Object Linking and Embedding (OLE) Compound File (CF) (i.e., OLECF)
file format, known as Compound Binary File format by Microsoft, used by
Microsoft Office 97-2003 applications (Word, Powerpoint, Excel, Wizard).
[See also Excel, Outlook, PowerPoint, and Word "subheaders" at byte offset 512 (0x200).]

There appear to several subheader formats and a dearth of documentation.
There have been reports that there are different subheaders for Windows and Mac
versions of MS Office but I cannot confirm that.]
Password-protected DOCX, XLSX, and PPTX files also use this signature those files
are saved as OLECF files.
[Note the similarity between D0 CF 11 E0 and the word "DOCFILE"!]


AC_
 
CaseWare Working Papers compressed client file


ADP
 
Access project file


APR
 
Lotus/IBM Approach 97 file


DB
 
MSWorks database file


MSC
 
Microsoft Common Console Document


MSG
 
Microsoft Outlook/Exchange Message


MSI
 
Microsoft Installer package


MSP
 
Windows Installer Patch


MTW
 
Minitab data file


MXD
 
ArcMap GIS project file


OPT
 
Developer Studio File Workspace Options file


PUB
 
MS Publisher file


QBM
 
QuickBooks Portable Company File


RVT
 
Revit Project file


SOU
 
Visual Studio Solution User Options file


SPO
 
SPSS output file


VSD
 
Visio file


WPS
 
MSWorks text document




D2 0A 00 00
 
Ò...


FTR
 
GN Nettest WinPharoah filter file




D4 2A
 
Ô*


ARL, AUT
 
AOL history (ARL) and typed URL (AUT) files




D4 C3 B2 A1
 
ÔÃ²¡


n/a
 
WinDump (winpcap) capture file (Windows)




D7 CD C6 9A
 
×ÍÆš


WMF
 
Windows graphics metafile




DB A5 2D 00
 
Û¥-.


DOC
 
Word 2.0 file




DC DC
 
ÜÜ


CPL
 
Corel color palette file




DC FE
 
Üþ


EFX
 
eFax file format




E3 10 00 01 00 00 00 00
 
ã.......


INFO
 
Amiga Icon file




E3 82 85 96
 
ã‚…–


PWL
 
Windows 98 password file




E4 52 5C 7B 8C D8 A7 4D
AE B1 53 78 D0 29 96 D3
 
äR\{ŒØ§M
®±SxÐ)–Ó


ONE
 
Microsoft OneNote note




E8 or
 
è


E9 or
 
é


EB
 
ë


COM, SYS
 
Windows executable file




EB 3C 90 2A
 
ë<.*


IMG
 
GEM Raster file




EB 52 90 2D 46 56 45 2D
46 53 2D
 
ëR.-FVE-
FS-


n/a
 
Header of boot sector in BitLocker protected volume (Vista)




EB 58 90 2D 46 56 45 2D
46 53 2D
 
ëX.-FVE-
FS-


n/a
 
Header of boot sector in BitLocker protected volume (Windows 7)




[512 (0x200) byte offset]
EC A5 C1 00
 
[512 (0x200) byte offset]
ì¥Á.


DOC
 
Word document subheader (MS Office)




ED AB EE DB
 
í«îÛ


RPM
 
RedHat Package Manager file




EF BB BF
 
ï»¿


n/a
 
Byte-order mark (BOM) for 8-bit Unicode Transformation Format
(UTF-8) files.
(See the Unicode Home Page.)




EF BB BF 3C
 
ï»¿<


WSF
 
Windows Script Component (UTF-8)




EF BB BF 3C 3F
 
ï»¿<?


WSC
 
Windows Script Component (UTF-8)




[At a cluster boundary]
F0 FF FF
 
[At a cluster boundary]
ðÿÿ


n/a
 
FAT12 File Allocation Table




[At a cluster boundary]
F8 FF FF FF
 
[At a cluster boundary]
øÿÿÿ


n/a
 
FAT16 File Allocation Table




[At a cluster boundary]
F8 FF FF 0F FF FF FF 0F
 
[At a cluster boundary]
øÿÿ.ÿÿÿ.


n/a
 
FAT32 File Allocation Table




[At a cluster boundary]
F8 FF FF 0F FF FF FF FF
 
[At a cluster boundary]
øÿÿ.ÿÿÿÿ


n/a
 
FAT32 File Allocation Table




F9 BE B4 D9
 
ù¾´Ù


DAT
 
Bitcoin-Qt blockchain block file




FD 37 7A 58 5A 00
 
ý7zXZ.



XZ
 
XZ archive file




[512 (0x200) byte offset]
FD FF FF FF 02
 
[512 (0x200) byte offset]
ýÿÿÿ.


PUB
 
MS Publisher file subheader




[512 (0x200) byte offset]
FD FF FF FF 04
 
[512 (0x200) byte offset]
ýÿÿÿ.


QBM
 
QuickBooks Portable Company File


SUO
 
Visual Studio Solution User Options subheader (MS Office)




[512 (0x200) byte offset]
FD FF FF FF nn nn 00 00
 
[512 (0x200) byte offset]
ýÿÿÿ....


PPT
 
PowerPoint presentation subheader (MS Office)




[512 (0x200) byte offset]
FD FF FF FF nn 00
 
[512 (0x200) byte offset]
ýÿÿÿ..


or




[512 (0x200) byte offset]
FD FF FF FF nn 02
 
[512 (0x200) byte offset]
ýÿÿÿ..


XLS
 
Excel spreadsheet subheader (MS Office)




[512 (0x200) byte offset]
FD FF FF FF 20 00 00 00
 
[512 (0x200) byte offset]
ýÿÿÿ ...


OPT
 
Developer Studio File Workspace Options subheader (MS Office)


XLS
 
Excel spreadsheet subheader (MS Office)




[512 (0x200) byte offset]
FD FF FF FF xx xx xx xx
xx xx xx xx 04 00 00 00
 
[512 (0x200) byte offset]
ýÿÿÿ....
........


DB
 
Thumbs.db subheader (MS Office)




FE ED FA CE
 
þíúÎ


n/a
 
Apple OS X ABI Mach-O binary file (32-bit)




FE ED FA CF
 
þíúÏ


n/a
 
Apple OS X ABI Mach-O binary file (64-bit)




FE ED FE ED
 
þíþí


JKS
 
JavaKeyStore file




FE EF
 
þï


GHO, GHS
 
Symantex Ghost image file




FE FF
 
þÿ


n/a
 
Byte-order mark (BOM) for 16-bit Unicode Transformation Format/
2-octet Universal Character Set (UTF-16/UCS-2), big-endian files.
(See the Unicode Home Page.)




FF
 
ÿ


SYS
 
Windows executable (SYS) file




FF 00 02 00 04 04 05 54
02 00
 
ÿ......T
..


WKS
 
Works for Windows spreadsheet file




FF 0A 00
 
ÿ..


QRP
 
QuickReport Report file




FF 46 4F 4E 54
 
ÿFONT


CPI
 
Windows international code page




FF 4B 45 59 42 20 20 20
 
ÿKEYB


SYS
 
Keyboard driver file




FF 57 50 43
 
ÿWPC


WP, WPD, WPG, WPP, WP5, WP6
 
WordPerfect text and graphics file




FF D8
 
ÿØ


JPE, JPEG, JPG
 
Generic JPEGimage file
Trailer: FF D9 (ÿÙ)




NOTES on JPEG file headers: The proper JPEG header is the two-byte sequence, 0xFF-D8, aka Start of Image (SOI) marker.
JPEG files end with the two-byte sequence, 0xFF-D9, aka End of Image (EOI) marker.

Between the SOI and EOI, JPEG files are composed of segments. Segments start with a two-byte Segment Tag followed by a
two-byte Segment Length field and then a zero-terminated string identifier (i.e., a character string followed by a 0x00), as
shown below with the JFIF, Exif, and SPIFF segments.

Segment Tags of the form 0x-FF-Ex (where x = 0..F) are referred to as APP0-APP15, and contain application-specific information. The
most commonly seen APP segments at the beginning of a JPEG file are APP0 and APP1 although others are also seen. Some additional
tags are shown below:


0xFF-D8-FF-E0 — Standard JPEG/JFIF file, as shown below.
0xFF-D8-FF-E1 — Standard JPEG file with Exif metadata, as shown below.
0xFF-D8-FF-E2 — Canon Camera Image File Format (CIFF) JPEG file (formerly used by some EOS and Powershot cameras).
0xFF-D8-FF-E8 — Still Picture Interchange File Format (SPIFF), as shown below.
FF D8 FF E0 xx xx 4A 46
49 46 00
 
ÿØÿà..JF
IF.


JFIF, JPE, JPEG, JPG
 
JPEG/JFIF graphics file
Trailer: FF D9 (ÿÙ)




FF D8 FF E1 xx xx 45 78
69 66 00
 
ÿØÿá..Ex
if.


JPG
 
Digital camera JPG using Exchangeable Image File Format (EXIF)
Trailer: FF D9 (ÿÙ)
See "Using Extended File Information (EXIF) File Headers in Digital
Evidence Analysis" (P. Alvarez, IJDE, 2(3), Winter 2004) and
ExifTool Tag Names




FF D8 FF E8 xx xx 53 50
49 46 46 00
 
ÿØÿè..SP
IFF.


JPG
 
Still Picture Interchange File Format (SPIFF)
Trailer: FF D9 (ÿÙ)




FF Ex
 
ÿ.


FF Fx
 
ÿ.


MPEG, MPG, MP3
 
MPEG audio file frame synch pattern




FF F1
 
ÿñ


AAC
 
MPEG-4 Advanced Audio Coding (AAC) Low Complexity (LC) audio file




FF F9
 
ÿù


AAC
 
MPEG-2 Advanced Audio Coding (AAC) Low Complexity (LC) audio file




FF FE
 
ÿþ


REG
 
Windows Registry file



n/a
 
Byte-order mark (BOM) for 16-bit Unicode Transformation Format/
2-octet Universal Character Set (UTF-16/UCS-2), little-endian files.
(See the Unicode Home Page.)




FF FE 00 00
 
ÿþ..


n/a
 
Byte-order mark for 32-bit Unicode Transformation Format/
4-octet Universal Character Set (UTF-32/UCS-4), little-endian files.
(See the Unicode Home Page.)




FF FE 23 00 6C 00 69 00
6E 00 65 00 20 00 31 00
 
ÿþ#.l.i.
n.e. .1.


MOF
 
Windows MSinfo file




FF FF FF FF
 
ÿÿÿÿ


SYS
 
DOS system driver



