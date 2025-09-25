---
title: HCMUS-CTF 2025 Qualification
published: 2024-07-20
description: "My contribution to this CTF"
image: "./hcmusctf.png"
tags: ["CTF", "Forensic", "Rev"]
category: Writeups
draft: false
---

## Team: Placetaker

# Forensic

## TLS Challenge

> Can you extract the flag from encrypted HTTPS?

In Wireshark, **Edit** -> **Preferences**, in **Protocol** selects **TLS** and set the given keylog file as *Master-Secret log file*.

![image](https://hackmd.io/_uploads/HyjiRFqLxx.png)

This will decrypt the encrypted HTTP traffic
![image](https://hackmd.io/_uploads/S1Rkyc5Lge.png)
Flag: `HCMUS-CTF{tls_tr@ffic_@n@lysis_ch@ll3ng3}`

## Disk Partition

> Too many flags... but only one is real.
> Download file [**here**](https://drive.google.com/file/d/1krXdDlmZpbQpFuTEs-fQc_lxq-hvjkgx/view).



That's alot of flag
![image](https://hackmd.io/_uploads/B1d0MFqLel.png)

Opening the image in FTK Imager reveals 3 partitions with alot of fake flag files
![image](https://hackmd.io/_uploads/B1UdVtqUle.png)


Since this is a disk image challenge so the next logical thing is to look for a deleted file, looking through the ***[unallocated spaces]*** files there is one with the flag

![image](https://hackmd.io/_uploads/Bk_MVYcIeg.png)

Flag: `HCMUS-CTF{1gn0r3_+h3_n01$3_f1nd_m@c}`

## File hidden

> Relax and chill with this lo-fi track... but listen caffuly — there might be something hidden in the sound waves.

I was given **JACK_J97_｜_THIÊN_LÝ_ƠI.wav**, using exiftool reveals that this masterpiece of a song has 2 channels, so I inspect their soundwaves in *Sonic Visualiser*.

![image](https://hackmd.io/_uploads/rkGxPKqUee.png)
After looking carefully I notice a suspicious part a the start of the song 
![image](https://hackmd.io/_uploads/BJP5Dt9Uxx.png)
Looks like some binary data for me
![image](https://hackmd.io/_uploads/S1b3wKcIgl.png)
Music file like .wav store there soundwaves data in their `data` section, using **HxD** I was able to see those waves

![image](https://hackmd.io/_uploads/r1ra_F9Ugl.png)
Extracting and decode them give us an archive which holds the flag

![image](https://hackmd.io/_uploads/rkmk5KqIge.png)

Flag: `HCMUS-CTF{Th13nLy_0i_J4ck_5M1ll10n}`

## Trashbin

> Someone’s been treating my computer like a trash bin, constantly dumping useless files into it. But it seems he got careless and dropped a really important one in there. Even though he deleted it afterward, it might have been too late—hehe😏.

Alot of SMB2 traffic in the given pcap file and alot of files.
![image](https://hackmd.io/_uploads/SkyWsY9Ilg.png)
![image](https://hackmd.io/_uploads/BkVSiKqUgx.png)

Exporting, unzipping those files results in a bunch of txts.
![image](https://hackmd.io/_uploads/SJz9Ttc8xl.png)

Using this command I was able to sort the file by there end number, and the last one stands out as an abnormally

```bash
ls *.txt|awk -F'[_.]' '{print $(NF-1)" "$0}'|sort -n|cut -d' ' -f2-
```
![image](https://hackmd.io/_uploads/B1KTaK9Ueg.png)

Flag: `HCMUS-CTF{pr0t3ct_y0ur_SMB_0r_d1e}`

# Reversing

## Finesse
> Yet another Tetris clone. Rumors say that there is something hidden inside.
> Visit https://finesse.blackpinker.com/ in your browser.

Following the link leads to a pdf tetris game.
![image](https://hackmd.io/_uploads/HyyOl95Ull.png)

I found this link https://github.com/ThomasRinsma/pdftris in which I learned that the game code is embeded in the pdf itself. So I download the pdf and run **binwalk** on it.

![image](https://hackmd.io/_uploads/HkxZWcqUgx.png)

And one of them was the game's obfuscated script.

```js
const a=10;const b=20;var c={0:["RGB",1.0,1.0,0.0],1:["RGB",0.0,1.0,1.0],2:["RGB",0.0,1.0,0.0],3:["RGB",1.0,0.0,0.0],4:["RGB",1.0,0.5,0.0],5:["RGB",0.0,0.0,1.0],6:["RGB",0.6,0.0,0.6]};function d(e,f){return app.setInterval("("+e.toString()+")();",f);}var g=Date.now()%2147483647;function h(){return g=g*16807%2147483647;}var i=[1,2,2,2,4,4,4];var j=[0,0,-1,0,-1,-1,0,-1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-2,0,-1,0,1,0,0,0,0,1,0,-1,0,-2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-1,-1,0,-1,1,0,0,0,0,1,1,0,1,-1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-1,0,0,-1,1,-1,0,0,1,1,1,0,0,-1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-1,0,-1,-1,1,0,0,0,0,1,0,-1,1,-1,0,0,-1,0,1,0,1,1,0,0,-1,1,0,1,0,-1,0,0,-1,0,1,0,1,-1,0,0,0,1,0,-1,1,1,0,0,-1,1,-1,0,1,0,0,0,0,1,0,-1,-1,-1,0,0,-1,0,0,-1,1,0,0,0,0,1,0,-1,1,0,0,0,-1,0,0,1,1,0,0,0,-1,0,0,1,0,-1];var k=50;var l=400;var m=[];var n=[];var o=0;var p=0;var q=0;var r=0;var s=[];var t=0;var u=false;var v=false;var w=h()%7;var x=0;var y=0;var z=0;function aa(){w=h()%7;x=4;y=0;z=0;for(var ab=0;ab<4;++ab){var ac=j[w*32+z*8+ab*2];var ad=j[w*32+z*8+ab*2+1];var ae=x+ac;var af=y+ad;if(ae>=0&&ae<a&&af>=0&&af<b){if(n[ae][af]!==0){an();return false;}}}return true;}function ag(ah){this.getField("T_input").hidden=!ah;this.getField("B_left").hidden=!ah;this.getField("B_right").hidden=!ah;this.getField("B_down").hidden=!ah;this.getField("B_rotate").hidden=!ah;}function ai(){for(var aj=0;aj<a;++aj){m[aj]=[];n[aj]=[];for(var ak=0;ak<b;++ak){m[aj][ak]=this.getField(`P_${aj}_${ak}`);n[aj][ak]=0;}}aa();q=p;o=0;u=true;r=d(cz,k);this.getField("B_start").hidden=true;ag(true);}function al(){var am=true;if(p-q>=l){am=bv();q=p;}return am;}function an(){u=false;app.clearInterval(r);for(var ao=0;ao<a;++ao){for(var ap=0;ap<b;++ap){m[ao][ap].fillColor=color.black;m[ao][ap].hidden=false;}}app.alert(`Game over! Score: ${o}\nRefresh to restart.`);}function aq(ar){if(ar===1){return[[0,0],[1,0],[-1,0],[2,0],[-2,0],[0,-1],[1,-1],[-1,-1],[0,-2]];}else{return[[0,0],[1,0],[-1,0],[0,-1],[1,-1],[-1,-1],[0,-2]];}}function as(){if(!u)return;t+=1;var at=z;var au=(z+1)%i[w];var av=aq(w);for(var aw=0;aw<av.length;aw++){var ax=av[aw][0];var ay=av[aw][1];var az=true;for(var ba=0;ba<4;++ba){var bb=j[w*32+au*8+ba*2];var bc=j[w*32+au*8+ba*2+1];var bd=x+bb+ax;var be=y+bc+ay;if(bd<0||bd>=a||be<0||be>=b||n[bd][be]!==0){az=false;break;}}if(az){z=au;x+=ax;y+=ay;return;}}}function bf(){if(!u)return;t+=2;x--;if(bh())x++;}function bg(){if(!u)return;t+=3;x++;if(bh())x--;}function bh(){for(var bi=0;bi<4;++bi){var bj=j[w*32+z*8+bi*2];var bk=j[w*32+z*8+bi*2+1];var bl=x+bj;var bm=y+bk;if(bl<0||bl>=a||n[bl][bm])return true;}return false;}function bn(bo){if(!u)return;switch(bo.change){case'w':as();break;case'a':bf();break;case'd':bg();break;case's':bv();break;case' ':cc();break;}}function bp(){for(var bq=0;bq<b;++bq){var br=true;for(var bs=0;bs<a;++bs){if(n[bs][bq]===0){br=false;break;}}if(br){o++;cj();for(var bt=bq;bt>0;--bt){for(var bu=0;bu<a;++bu){n[bu][bt]=n[bu][bt-1];}}for(var bu=0;bu<a;++bu){n[bu][0]=0;}bq--;}}}function bv(){var bw=false;y++;for(var bx=0;bx<4;++bx){var by=j[w*32+z*8+bx*2];var bz=j[w*32+z*8+bx*2+1];var ca=x+by;var cb=y+bz;if(ca<0||cb<0||ca>=a||cb>=b||n[ca][cb]){bw=true;break;}}if(bw){y--;for(var bx=0;bx<4;++bx){var by=j[w*32+z*8+bx*2];var bz=j[w*32+z*8+bx*2+1];var ca=x+by;var cb=y+bz;if(cb<0){an();return false;}}for(var bx=0;bx<4;++bx){var by=j[w*32+z*8+bx*2];var bz=j[w*32+z*8+bx*2+1];var ca=x+by;var cb=y+bz;n[ca][cb]=w+1;}bp();s.push(t%32);t=0;da();return aa();}return true;}function cc(){while(true){y++;var cd=false;for(var ce=0;ce<4;++ce){var cf=j[w*32+z*8+ce*2];var cg=j[w*32+z*8+ce*2+1];var ch=x+cf;var ci=y+cg;if(ch<0||ci<0||ch>=a||ci>=b||n[ch][ci]){cd=true;break;}}if(cd){y--;bv();break;}}}function cj(){if(v)return;this.getField("T_score").value=`Score: ${o}`;}function ck(cl,cm,cn){if(cl<0||cm<0||cl>=a||cm>=b)return;var co=m[cl][b-1-cm];if(cn){co.hidden=false;co.fillColor=c[cn-1];}else{co.hidden=true;co.fillColor=color.transparent;}}function cp(){for(var cq=0;cq<a;++cq){for(var cr=0;cr<b;++cr){ck(cq,cr,n[cq][cr]);}}}function cs(){for(var ct=0;ct<4;++ct){var cu=j[w*32+z*8+ct*2];var cv=j[w*32+z*8+ct*2+1];var cw=x+cu;var cx=y+cv;ck(cw,cx,w+1);}}function cy(){cp();cs();}function cz(){if(!u)return;p+=k;if(al())cy();}function da(){var db=s.length-1;for(var dc=0;dc<129;dc++){var dd=parseInt(this.getField(`M_${dc}`).value);var de=parseInt(this.getField(`M_${dc}_${db}`).value);this.getField(`M_${dc}`).value=dd+de*s[db];}if(db==128){for(var dc=0;dc<129;dc++){if(this.getField(`M_${dc}`).value!=this.getField(`G_${dc}`).value){s=[];return;}}df();}}function df(){u=false;v=true;var dg="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";var dh="";for(var di=0;di<s.length/3;di++){dh+=dg[s[3*di]+s[3*di+1]+s[3*di+2]];}app.alert(`${dh}`);}ag(false);app.execMenuItem("FitPage");
```

Deobsfucate this on https://deobfuscate.io gives us a clean looking code, the flag checking logic is at these functions

```js
[...]
function da() {
  var db = s.length - 1;
  for (var dc = 0; dc < 129; dc++) {
    var dd = parseInt(this.getField(`M_${dc}`).value);
    var de = parseInt(this.getField(`M_${dc}_${db}`).value);
    this.getField(`M_${dc}`).value = dd + de * s[db];
  }
  if (db == 128) {
    for (var dc = 0; dc < 129; dc++) {
      if (this.getField(`M_${dc}`).value != this.getField(`G_${dc}`).value) {
        s = [];
        return;
      }
    }
    df();
  }
}
function df() {
  u = false;
  v = true;
  var dg = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
  var dh = "";
  for (var di = 0; di < s.length / 3; di++) {
    dh += dg[s[3 * di] + s[3 * di + 1] + s[3 * di + 2]];
  }
  app.alert(`${dh}`);
}
[...]
```

The input `s` is multipled with a build-in 129x129 matrix (*objects M_\*\_\**) and checked with a 129 element array (*objects G\_\**), here is the solve script

```python
import sys, re
import numpy as np
from pypdf import PdfReader
import logging; logging.getLogger("pypdf").setLevel(logging.ERROR)

pdf_path = sys.argv[1] if len(sys.argv) > 1 else "main.pdf"
fields = PdfReader(pdf_path).get_fields()

A = np.zeros((129, 129), dtype=np.int64)
b = np.zeros(129, dtype=np.int64)

rowcol = re.compile(r"M_(\d+)_(\d+)$")
g_row  = re.compile(r"G_(\d+)$")

for name, obj in fields.items():
    m = rowcol.fullmatch(name)
    if m:
        row, col = map(int, m.groups())
        A[row, col] = int(obj if isinstance(obj, str)
                          else obj.get("/V") or 0)
        continue
    g = g_row.fullmatch(name)
    if g:
        row = int(g.group(1))
        b[row] = int(obj if isinstance(obj, str)
                     else obj.get("/V") or 0)

s = np.linalg.solve(A, b).round().astype(int)

alphabet = ("abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")

flag = "".join(alphabet[s[i]+s[i+1]+s[i+2]]
               for i in range(0, 129, 3))

print("flag:", flag)

```

Flag: `HCMUS-CTF{w0w_u_r3a11y_r_4_T4Tr15_g0d_huh?}`

## Hide and Seek

> Something feels odd about this flag checker...

The file is heavily obsfucated with anti-decompiled techniques, well play HuyTrinh. Using IDA's debug I was able to view the assembly intrucstions

### main
```
.text:000055555555590B mov     rsi, rax
.text:000055555555590E mov     edi, 8
.text:0000555555555913 call    _signal
.text:0000555555555918 mov     rax, [rbp-70h]
.text:000055555555591C mov     rax, [rax]
.text:000055555555591F mov     cs:qword_55555555B958, rax
.text:0000555555555926 mov     eax, cs:dword_55555555B934
.text:000055555555592C test    eax, eax
.text:000055555555592E jz      short loc_5555555559A4
.text:0000555555555930 cmp     dword ptr [rbp-64h], 1 // Start with "l3"
.text:0000555555555934 jle     short loc_55555555595E
.text:0000555555555936 mov     rax, [rbp-70h]
.text:000055555555593A add     rax, 8
.text:000055555555593E mov     rax, [rax]
.text:0000555555555941 movzx   eax, byte ptr [rax]
.text:0000555555555944 cmp     al, 6Ch ; 'l'
.text:0000555555555946 jnz     short loc_55555555595E
.text:0000555555555948 mov     rax, [rbp-70h]
.text:000055555555594C add     rax, 8
.text:0000555555555950 mov     rax, [rax]
.text:0000555555555953 add     rax, 1
.text:0000555555555957 movzx   eax, byte ptr [rax]
.text:000055555555595A cmp     al, 33h ; '3'
.text:000055555555595C jz      short loc_5555555559A4
.text:000055555555595E
.text:000055555555595E loc_55555555595E:                       ; CODE XREF: .text:0000555555555934↑j
.text:000055555555595E                                         ; .text:0000555555555946↑j
.text:000055555555595E mov     ecx, 3
.text:0000555555555963 lea     rax, aNo                        ; "no\n"
.text:000055555555596A mov     rdx, rax
.text:000055555555596D mov     esi, 1
.text:0000555555555972 mov     edi, 1
.text:0000555555555977 mov     eax, 0
.text:000055555555597C call    _syscall
.text:0000555555555981 mov     rax, cs:qword_55555555B958
.text:0000555555555988 mov     rdi, rax
.text:000055555555598B call    loc_555555555267
.text:0000555555555990 mov     esi, 1
.text:0000555555555995 mov     edi, 3Ch ; '<'
.text:000055555555599A mov     eax, 0
.text:000055555555599F call    _syscall
.text:00005555555559A4
.text:00005555555559A4 loc_5555555559A4:                       ; CODE XREF: .text:000055555555592E↑j
.text:00005555555559A4                                         ; .text:000055555555595C↑j
.text:00005555555559A4 mov     ecx, cs:dword_55555555B934
.text:00005555555559AA mov     eax, 1
.text:00005555555559AF mov     edx, 0
.text:00005555555559B4 div     ecx            // 1 chia ecx
.text:00005555555559B6 mov     [rbp-50h], eax // Store quotient in rbp-50h
.text:00005555555559B9 mov     eax, cs:dword_55555555B934
.text:00005555555559BF sub     eax, 1
.text:00005555555559C2 mov     edx, eax
.text:00005555555559C4 lea     rax, unk_55555555B900
.text:00005555555559CB movzx   eax, byte ptr [rdx+rax]
.text:00005555555559CF mov     [rbp-57h], al
.text:00005555555559D2 mov     eax, cs:dword_55555555B930
.text:00005555555559D8 mov     [rbp-56h], al
.text:00005555555559DB movzx   eax, byte ptr [rbp-57h]
.text:00005555555559DF xor     al, [rbp-56h]
.text:00005555555559E2 mov     [rbp-55h], al
.text:00005555555559E5 mov     eax, cs:dword_55555555B934
.text:00005555555559EB sub     eax, 1
.text:00005555555559EE mov     edx, eax
.text:00005555555559F0 lea     rax, unk_555555556020
.text:00005555555559F7 movzx   eax, byte ptr [rdx+rax]
.text:00005555555559FB cmp     [rbp-55h], al
.text:00005555555559FE jz      short loc_555555555A46
.text:0000555555555A00 mov     ecx, 3
.text:0000555555555A05 lea     rax, aNo                        ; "no\n"
.text:0000555555555A0C mov     rdx, rax
.text:0000555555555A0F mov     esi, 1
.text:0000555555555A14 mov     edi, 1
.text:0000555555555A19 mov     eax, 0
.text:0000555555555A1E call    _syscall
.text:0000555555555A23 mov     rax, cs:qword_55555555B958
.text:0000555555555A2A mov     rdi, rax
.text:0000555555555A2D call    loc_555555555267
.text:0000555555555A32 mov     esi, 1
.text:0000555555555A37 mov     edi, 3Ch ; '<'
.text:0000555555555A3C mov     eax, 0
.text:0000555555555A41 call    _syscall
.text:0000555555555A46
.text:0000555555555A46 loc_555555555A46:                       ; CODE XREF: .text:00005555555559FE↑j
.text:0000555555555A46 mov     eax, cs:dword_55555555B934
.text:0000555555555A4C cmp     eax, 2Eh ; '.'
.text:0000555555555A4F jnz     short loc_555555555ACC
.text:0000555555555A51 mov     ecx, 3
.text:0000555555555A56 lea     rax, aOk                        ; "ok\n"
.text:0000555555555A5D mov     rdx, rax
.text:0000555555555A60 mov     esi, 1
.text:0000555555555A65 mov     edi, 1
.text:0000555555555A6A mov     eax, 0
.text:0000555555555A6F call    _syscall
.text:0000555555555A74 mov     dword ptr [rbp-54h], 0
.text:0000555555555A7B jmp     short loc_555555555A8B
.text:0000555555555A7D ; ---------------------------------------------------------------------------
.text:0000555555555A7D
.text:0000555555555A7D loc_555555555A7D:                       ; CODE XREF: .text:0000555555555A8F↓j
.text:0000555555555A7D mov     eax, [rbp-54h]
.text:0000555555555A80 cdqe
.text:0000555555555A82 mov     byte ptr [rbp+rax-40h], 0AAh
.text:0000555555555A87 add     dword ptr [rbp-54h], 1
.text:0000555555555A8B
.text:0000555555555A8B loc_555555555A8B:                       ; CODE XREF: .text:0000555555555A7B↑j
.text:0000555555555A8B cmp     dword ptr [rbp-54h], 2Dh ; '-'
.text:0000555555555A8F jle     short loc_555555555A7D
.text:0000555555555A91 mov     dword ptr [rbp-4Ch], 13371337h
.text:0000555555555A98 mov     dword ptr [rbp-48h], 0
.text:0000555555555A9F mov     rax, cs:qword_55555555B958
.text:0000555555555AA6 mov     ecx, [rbp-48h]
.text:0000555555555AA9 lea     rdx, [rbp-40h]
.text:0000555555555AAD mov     esi, [rbp-4Ch]
.text:0000555555555AB0 mov     rdi, rax
.text:0000555555555AB3 call    loc_5555555553C4
.text:0000555555555AB8 mov     esi, 0
.text:0000555555555ABD mov     edi, 3Ch ; '<'
.text:0000555555555AC2 mov     eax, 0
.text:0000555555555AC7 call    _syscall
.text:0000555555555ACC
.text:0000555555555ACC loc_555555555ACC:                       ; CODE XREF: .text:0000555555555A4F↑j
.text:0000555555555ACC lea     rax, dword_55555555B930
.text:0000555555555AD3 mov     rdi, rax
.text:0000555555555AD6 call    loc_555555555189                      // pseudo-random number generation
.text:0000555555555ADB mov     [rbp-44h], eax
.text:0000555555555ADE mov     rdx, cs:qword_55555555B958
.text:0000555555555AE5 mov     eax, cs:dword_55555555B934
.text:0000555555555AEB add     eax, 1
.text:0000555555555AEE mov     esi, eax
.text:0000555555555AF0 mov     eax, [rbp-44h]
.text:0000555555555AF3 mov     rcx, rdx
.text:0000555555555AF6 mov     edx, esi
.text:0000555555555AF8 lea     rsi, unk_55555555B900
.text:0000555555555AFF mov     edi, eax
.text:0000555555555B01 call    loc_5555555556F6
.text:0000555555555B06 mov     eax, 0
.text:0000555555555B0B mov     rdx, [rbp-8]
.text:0000555555555B0F sub     rdx, fs:28h
.text:0000555555555B18 jz      short locret_555555555B1F
.text:0000555555555B1A call    ___stack_chk_fail
.text:0000555555555B1F ; ---------------------------------------------------------------------------
.text:0000555555555B1F
.text:0000555555555B1F locret_555555555B1F:                    ; CODE XREF: .text:0000555555555B18↑j
.text:0000555555555B1F leave
.text:0000555555555B20 retn
.text:0000555555555B20 _text ends
```
### loc_5555555551C2
```
.text:00005555555551C2 loc_5555555551C2:                       ; CODE XREF: .text:0000555555555888↓p
.text:00005555555551C2 endbr64
.text:00005555555551C6 push    rbp
.text:00005555555551C7 mov     rbp, rsp
.text:00005555555551CA sub     rsp, 38h
.text:00005555555551CE mov     [rbp-28h], rdi   // input
.text:00005555555551D2 mov     [rbp-30h], rsi   // 0x2E
.text:00005555555551D6 mov     [rbp-38h], rdx   
.text:00005555555551DA jnz     near ptr loc_5555555551E6+1
.text:00005555555551E0 jz      near ptr loc_5555555551E6+1
.text:00005555555551E6
.text:00005555555551E6 loc_5555555551E6:                       ; CODE XREF: .text:00005555555551DA↑j
.text:00005555555551E6                                         ; .text:00005555555551E0↑j
.text:00005555555551E6 jmp     near ptr 5555259ADD33h
.text:00005555555551EB ; ---------------------------------------------------------------------------
.text:00005555555551EB sub     rax, 1
.text:00005555555551EF mov     [rbp-10h], rax
.text:00005555555551F3 jmp     short loc_55555555525C
.text:00005555555551F5 ; ---------------------------------------------------------------------------
.text:00005555555551F5
.text:00005555555551F5 loc_5555555551F5:                       ; CODE XREF: .text:0000555555555261↓j
.text:00005555555551F5 mov     rax, [rbp-38h]
.text:00005555555551F9 mov     rdi, rax
.text:00005555555551FC call    loc_555555555189  // pseudo-random number generation
.text:0000555555555201 mov     edx, eax
.text:0000555555555203 mov     rax, [rbp-10h]
.text:0000555555555207 lea     rcx, [rax+1]
.text:000055555555520B mov     rax, rdx
.text:000055555555520E mov     edx, 0
.text:0000555555555213 div     rcx
.text:0000555555555216 mov     [rbp-8], rdx
.text:000055555555521A mov     rdx, [rbp-28h]
.text:000055555555521E mov     rax, [rbp-10h]
.text:0000555555555222 add     rax, rdx
.text:0000555555555225 movzx   eax, byte ptr [rax]
.text:0000555555555228 mov     [rbp-11h], al
.text:000055555555522B mov     rdx, [rbp-28h]
.text:000055555555522F mov     rax, [rbp-8]
.text:0000555555555233 add     rax, rdx
.text:0000555555555236 mov     rcx, [rbp-28h]
.text:000055555555523A mov     rdx, [rbp-10h]
.text:000055555555523E add     rdx, rcx
.text:0000555555555241 movzx   eax, byte ptr [rax]
.text:0000555555555244 mov     [rdx], al
.text:0000555555555246 mov     rdx, [rbp-28h]
.text:000055555555524A mov     rax, [rbp-8]
.text:000055555555524E add     rdx, rax
.text:0000555555555251 movzx   eax, byte ptr [rbp-11h]
.text:0000555555555255 mov     [rdx], al
.text:0000555555555257 sub     qword ptr [rbp-10h], 1
.text:000055555555525C
.text:000055555555525C loc_55555555525C:                       ; CODE XREF: .text:00005555555551F3↑j
.text:000055555555525C cmp     qword ptr [rbp-10h], 0
.text:0000555555555261 jnz     short loc_5555555551F5
.text:0000555555555263 nop
.text:0000555555555264 nop
.text:0000555555555265 leave
.text:0000555555555266 retn
```

### SIGFPE handler
```
.text:000055555555577B mov     qword ptr [rbp-38h], 0
.text:0000555555555783 mov     qword ptr [rbp-30h], 0
.text:000055555555578B mov     qword ptr [rbp-28h], 0
.text:0000555555555793 mov     qword ptr [rbp-20h], 0
.text:000055555555579B mov     qword ptr [rbp-18h], 0

WRIRE "> "
.text:00005555555557A3 mov     ecx, 2
.text:00005555555557A8 lea     rax, asc_555555556063           ; "> "
.text:00005555555557AF mov     rdx, rax
.text:00005555555557B2 mov     esi, 1
.text:00005555555557B7 mov     edi, 1
.text:00005555555557BC mov     eax, 0
.text:00005555555557C1 call    _syscall

READ 0x2F BYTES FROM STDIN
.text:00005555555557C6 lea     rax, [rbp-40h]
.text:00005555555557CA mov     ecx, 2Fh ; '/'
.text:00005555555557CF mov     rdx, rax
.text:00005555555557D2 mov     esi, 0
.text:00005555555557D7 mov     edi, 0
.text:00005555555557DC mov     eax, 0
.text:00005555555557E1 call    _syscall

.text:00005555555557E6 mov     [rbp-78h], rax
.text:00005555555557EA cmp     qword ptr [rbp-78h], 2Dh ; '-'
.text:00005555555557EF jle     short loc_555555555801
.text:00005555555557F1 movzx   eax, byte ptr [rbp-12h]
.text:00005555555557F5 cmp     al, 0Ah
.text:00005555555557F7 jz      short loc_555555555847
.text:00005555555557F9 movzx   eax, byte ptr [rbp-12h]
.text:00005555555557FD test    al, al
.text:00005555555557FF jz      short loc_555555555847
.text:0000555555555801
.text:0000555555555801 loc_555555555801:                       ; CODE XREF: .text:00005555555557EF↑j
.text:0000555555555801 mov     ecx, 3
.text:0000555555555806 lea     rax, aNo                        ; "no\n"
.text:000055555555580D mov     rdx, rax
.text:0000555555555810 mov     esi, 1
.text:0000555555555815 mov     edi, 1
.text:000055555555581A mov     eax, 0
.text:000055555555581F call    _syscall
.text:0000555555555824 mov     rax, cs:qword_55555555B958
.text:000055555555582B mov     rdi, rax
.text:000055555555582E call    loc_555555555267
.text:0000555555555833 mov     esi, 1
.text:0000555555555838 mov     edi, 3Ch ; '<'
.text:000055555555583D mov     eax, 0
.text:0000555555555842 call    _syscall
.text:0000555555555847
.text:0000555555555847 loc_555555555847:                       ; CODE XREF: .text:00005555555557F7↑j
.text:0000555555555847                                         ; .text:00005555555557FF↑j
.text:0000555555555847 mov     dword ptr [rbp-7Ch], 0
.text:000055555555584E jmp     short loc_555555555869
.text:0000555555555850 ; ---------------------------------------------------------------------------
.text:0000555555555850
.text:0000555555555850 loc_555555555850:                       ; CODE XREF: .text:000055555555586D↓j
.text:0000555555555850 mov     eax, [rbp-7Ch]
.text:0000555555555853 cdqe
.text:0000555555555855 movzx   eax, byte ptr [rbp+rax-40h]
.text:000055555555585A mov     edx, eax
.text:000055555555585C mov     eax, [rbp-7Ch]
.text:000055555555585F cdqe
.text:0000555555555861 mov     [rbp+rax-70h], dl
.text:0000555555555865 add     dword ptr [rbp-7Ch], 1
.text:0000555555555869
.text:0000555555555869 loc_555555555869:                       ; CODE XREF: .text:000055555555584E↑j
.text:0000555555555869 cmp     dword ptr [rbp-7Ch], 2Dh ; '-'
.text:000055555555586D jle     short loc_555555555850
.text:000055555555586F mov     eax, cs:dword_55555555B930
.text:0000555555555875 mov     [rbp-80h], eax
.text:0000555555555878 lea     rdx, [rbp-80h]
.text:000055555555587C lea     rax, [rbp-70h] 
.text:0000555555555880 mov     esi, 2Eh ; '.'
.text:0000555555555885 mov     rdi, rax
.text:0000555555555888 call    loc_5555555551C2            // shuffle function
.text:000055555555588D mov     rdx, cs:qword_55555555B958
.text:0000555555555894 mov     eax, [rbp-80h]
.text:0000555555555897 lea     rsi, [rbp-70h]
.text:000055555555589B mov     rcx, rdx
.text:000055555555589E mov     edx, 1
.text:00005555555558A3 mov     edi, eax
.text:00005555555558A5 call    loc_5555555556F6     
.text:00005555555558AA mov     esi, 0
.text:00005555555558AF mov     edi, 3Ch ; '<'
.text:00005555555558B4 mov     eax, 0
.text:00005555555558B9 call    _syscall
.text:00005555555558BE nop
.text:00005555555558BF mov     rax, [rbp-8]
.text:00005555555558C3 sub     rax, fs:28h
.text:00005555555558CC jz      short near ptr loc_5555555558D2+1
.text:00005555555558CC ; ---------------------------------------------------------------------------
.text:00005555555558CE db 0E8h
.text:00005555555558CF db  9Dh
.text:00005555555558D0 ; ---------------------------------------------------------------------------
.text:00005555555558D0 idiv    edi
.text:00005555555558D2
.text:00005555555558D2 loc_5555555558D2:                       ; CODE XREF: .text:00005555555558CC↑j
.text:00005555555558D2 dec     ecx
.text:00005555555558D4 retn
```

### loc_5555555556F6
```
.text:00005555555556F6 loc_5555555556F6:                       ; CODE XREF: .text:00005555555558A5↓p
.text:00005555555556F6                                         ; .text:0000555555555B01↓p
.text:00005555555556F6 endbr64
.text:00005555555556FA push    rbp
.text:00005555555556FB mov     rbp, rsp
.text:00005555555556FE sub     rsp, 20h
.text:0000555555555702 mov     [rbp-4], edi   // PRNG
.text:0000555555555705 mov     [rbp-10h], rsi // input
.text:0000555555555709 mov     [rbp-8], edx   // current counter?
.text:000055555555570C mov     [rbp-18h], rcx
.text:0000555555555710 jnz     near ptr loc_55555555571C+1
.text:0000555555555716 jz      near ptr loc_55555555571C+1
.text:000055555555571C
.text:000055555555571C loc_55555555571C:                       ; CODE XREF: .text:0000555555555710↑j
.text:000055555555571C                                         ; .text:0000555555555716↑j
.text:000055555555571C jmp     near ptr 55559E4DA4ACh
.text:0000555555555721 ; ---------------------------------------------------------------------------
.text:0000555555555721 mov     edx, [rbp-10h]
.text:0000555555555724 mov     esi, [rbp-4]
.text:0000555555555727 mov     rax, [rbp-18h]
.text:000055555555572B mov     rdi, rax
.text:000055555555572E call    loc_5555555553C4
.text:0000555555555733 mov     rax, [rbp-18h]
.text:0000555555555737 mov     rdi, rax
.text:000055555555573A call    loc_55555555565E
.text:000055555555573F nop
.text:0000555555555740 leave
.text:0000555555555741 retn
```
### loc_5555555553C4
```
.text:00005555555553C4 endbr64
.text:00005555555553C8 push    rbp
.text:00005555555553C9 mov     rbp, rsp
.text:00005555555553CC sub     rsp, 0D0h
.text:00005555555553D3 mov     [rbp-0B8h], rdi
.text:00005555555553DA mov     [rbp-0BCh], esi // psudo random
.text:00005555555553E0 mov     [rbp-0C8h], rdx
.text:00005555555553E7 mov     [rbp-0C0h], ecx
.text:00005555555553ED mov     rax, fs:28h
.text:00005555555553F6 mov     [rbp-8], rax
.text:00005555555553FA xor     eax, eax
.text:00005555555553FC jnz     near ptr loc_555555555408+1
.text:0000555555555402 jz      near ptr loc_555555555408+1
.text:0000555555555408
.text:0000555555555408 loc_555555555408:                       ; CODE XREF: .text:00005555555553FC↑j
.text:0000555555555408                                         ; .text:0000555555555402↑j
.text:0000555555555408 jmp     near ptr 555555560C4Eh
.text:0000555555555408 ; ---------------------------------------------------------------------------
.text:000055555555540D db    0
.text:000055555555540E db    0
.text:000055555555540F ; ---------------------------------------------------------------------------
.text:000055555555540F mov     ecx, 0
.text:0000555555555414 lea     rax, aProcSelfExe               ; "/proc/self/exe"
.text:000055555555541B mov     rdx, rax
.text:000055555555541E mov     esi, 0FFFFFF9Ch
.text:0000555555555423 mov     edi, 101h
.text:0000555555555428 mov     eax, 0
.text:000055555555542D call    _syscall                  // openat(AT_FDCWD, "/proc/self/exe", O_RDONLY)
.text:0000555555555432 mov     [rbp-0ACh], eax
.text:0000555555555438 cmp     dword ptr [rbp-0ACh], 0
.text:000055555555543F jns     short loc_555555555455
.text:0000555555555441 mov     esi, 1
.text:0000555555555446 mov     edi, 3Ch ; '<'
.text:000055555555544B mov     eax, 0
.text:0000555555555450 call    _syscall                  // sys_exit

.text:0000555555555455
.text:0000555555555455 loc_555555555455:                       ; CODE XREF: .text:000055555555543F↑j
.text:0000555555555455 lea     rdx, [rbp-0A0h]
.text:000055555555545C mov     eax, [rbp-0ACh]
.text:0000555555555462 mov     esi, eax
.text:0000555555555464 mov     edi, 5
.text:0000555555555469 mov     eax, 0
.text:000055555555546E call    _syscall               // fills statbuf


.text:0000555555555473 mov     rax, [rbp-70h]
.text:0000555555555477 sub     rsp, 8
.text:000055555555547B push    0
.text:000055555555547D mov     r9d, 0FFFFFFFFh
.text:0000555555555483 mov     r8d, 22h ; '"'
.text:0000555555555489 mov     ecx, 3
.text:000055555555548E mov     rdx, rax
.text:0000555555555491 mov     esi, 0
.text:0000555555555496 mov     edi, 9
.text:000055555555549B mov     eax, 0
.text:00005555555554A0 call    _syscall               // mmap(NULL, size, PROT_RW, MAP_PRIVATE|MAP_ANON, -1, 0)
.text:00005555555554A5 add     rsp, 10h
.text:00005555555554A9 mov     [rbp-0A8h], rax
.text:00005555555554B0 mov     rax, [rbp-0A8h]
.text:00005555555554B7 test    rax, rax
.text:00005555555554BA jns     short loc_5555555554D0
.text:00005555555554BC mov     esi, 1
.text:00005555555554C1 mov     edi, 3Ch ; '<'
.text:00005555555554C6 mov     eax, 0
.text:00005555555554CB call    _syscall                // sys_exit
.text:00005555555554D0
.text:00005555555554D0 loc_5555555554D0:                       ; CODE XREF: .text:00005555555554BA↑j
.text:00005555555554D0 mov     rcx, [rbp-70h]
.text:00005555555554D4 mov     rdx, [rbp-0A8h]
.text:00005555555554DB mov     eax, [rbp-0ACh]
.text:00005555555554E1 mov     esi, eax
.text:00005555555554E3 mov     edi, 0
.text:00005555555554E8 mov     eax, 0
.text:00005555555554ED call    _syscall               // sys_read(fd, mapped_ptr, size)
.text:00005555555554F2 mov     eax, [rbp-0ACh]
.text:00005555555554F8 mov     esi, eax
.text:00005555555554FA mov     edi, 3
.text:00005555555554FF mov     eax, 0
.text:0000555555555504 call    _syscall               // sys_close(fd)
.text:0000555555555509 mov     dword ptr [rbp-0B0h], 0
.text:0000555555555513 jmp     short loc_555555555551

.text:0000555555555515 ; ---------------------------------------------------------------------------
.text:0000555555555515
.text:0000555555555515 loc_555555555515:                       ; CODE XREF: .text:0000555555555558↓j
.text:0000555555555515 mov     eax, [rbp-0B0h]
.text:000055555555551B movsxd  rdx, eax
.text:000055555555551E mov     rax, [rbp-0C8h]
.text:0000555555555525 add     rax, rdx
.text:0000555555555528 mov     edx, [rbp-0B0h]
.text:000055555555552E movsxd  rcx, edx
.text:0000555555555531 mov     rdx, cs:qword_55555555B938     // 55555555B900
.text:0000555555555538 add     rcx, rdx
.text:000055555555553B mov     rdx, [rbp-0A8h]
.text:0000555555555542 add     rdx, rcx
.text:0000555555555545 movzx   eax, byte ptr [rax]
.text:0000555555555548 mov     [rdx], al
.text:000055555555554A add     dword ptr [rbp-0B0h], 1
.text:0000555555555551
.text:0000555555555551 loc_555555555551:                       ; CODE XREF: .text:0000555555555513↑j
.text:0000555555555551 cmp     dword ptr [rbp-0B0h], 2Dh ; '-'
.text:0000555555555558 jle     short loc_555555555515
.text:000055555555555A mov     rdx, cs:qword_55555555B940     // 55555555B930
.text:0000555555555561 mov     rax, [rbp-0A8h]
.text:0000555555555568 add     rdx, rax
.text:000055555555556B mov     eax, [rbp-0BCh]
.text:0000555555555571 mov     [rdx], eax
.text:0000555555555573 mov     rdx, cs:qword_55555555B948     // 55555555B934
.text:000055555555557A mov     rax, [rbp-0A8h]
.text:0000555555555581 add     rdx, rax
.text:0000555555555584 mov     eax, [rbp-0C0h]
.text:000055555555558A mov     [rdx], eax
.text:000055555555558C mov     rax, [rbp-0B8h]
.text:0000555555555593 mov     rsi, rax
.text:0000555555555596 mov     edi, 57h ; 'W'
.text:000055555555559B mov     eax, 0
.text:00005555555555A0 call    _syscall                                 // unlink
.text:00005555555555A5 mov     rax, [rbp-0B8h]
.text:00005555555555AC mov     r8d, 1C0h
.text:00005555555555B2 mov     ecx, 241h
.text:00005555555555B7 mov     rdx, rax
.text:00005555555555BA mov     esi, 0FFFFFF9Ch
.text:00005555555555BF mov     edi, 101h
.text:00005555555555C4 mov     eax, 0
.text:00005555555555C9 call    _syscall
.text:00005555555555CE mov     [rbp-0ACh], eax
.text:00005555555555D4 cmp     dword ptr [rbp-0ACh], 0
.text:00005555555555DB jns     short loc_5555555555F1
.text:00005555555555DD mov     esi, 1
.text:00005555555555E2 mov     edi, 3Ch ; '<'
.text:00005555555555E7 mov     eax, 0
.text:00005555555555EC call    _syscall
.text:00005555555555F1
.text:00005555555555F1 loc_5555555555F1:                       ; CODE XREF: .text:00005555555555DB↑j
.text:00005555555555F1 mov     rcx, [rbp-70h]
.text:00005555555555F5 mov     rdx, [rbp-0A8h]
.text:00005555555555FC mov     eax, [rbp-0ACh]
.text:0000555555555602 mov     esi, eax
.text:0000555555555604 mov     edi, 1
.text:0000555555555609 mov     eax, 0
.text:000055555555560E call    _syscall
.text:0000555555555613 mov     eax, [rbp-0ACh]
.text:0000555555555619 mov     esi, eax
.text:000055555555561B mov     edi, 3
.text:0000555555555620 mov     eax, 0
.text:0000555555555625 call    _syscall
.text:000055555555562A mov     rdx, [rbp-70h]
.text:000055555555562E mov     rax, [rbp-0A8h]
.text:0000555555555635 mov     rsi, rax
.text:0000555555555638 mov     edi, 0Bh
.text:000055555555563D mov     eax, 0
.text:0000555555555642 call    _syscall
.text:0000555555555647 nop
.text:0000555555555648 mov     rax, [rbp-8]
.text:000055555555564C sub     rax, fs:28h
.text:0000555555555655 jz      short locret_55555555565C
.text:0000555555555657 call    ___stack_chk_fail
.text:000055555555565C ; ---------------------------------------------------------------------------
.text:000055555555565C
.text:000055555555565C locret_55555555565C:                    ; CODE XREF: .text:0000555555555655↑j
.text:000055555555565C leave
.text:000055555555565D retn
```
### loc_55555555565E 
```
.text:000055555555565E loc_55555555565E:                       ; CODE XREF: .text:000055555555573A↓p
.text:000055555555565E endbr64
.text:0000555555555662 push    rbp
.text:0000555555555663 mov     rbp, rsp
.text:0000555555555666 sub     rsp, 40h
.text:000055555555566A mov     [rbp-38h], rdi
.text:000055555555566E mov     rax, fs:28h
.text:0000555555555677 mov     [rbp-8], rax
.text:000055555555567B xor     eax, eax
.text:000055555555567D jnz     near ptr loc_555555555689+1
.text:0000555555555683 jz      near ptr loc_555555555689+1
.text:0000555555555689
.text:0000555555555689 loc_555555555689:                       ; CODE XREF: .text:000055555555567D↑j
.text:0000555555555689                                         ; .text:0000555555555683↑j
.text:0000555555555689 jmp     near ptr 55551D9AE1D6h
.text:000055555555568E ; ---------------------------------------------------------------------------
.text:000055555555568E mov     [rbp-20h], rax
.text:0000555555555692 lea     rax, aL33t                      ; "l33t"
.text:0000555555555699 mov     [rbp-18h], rax
.text:000055555555569D mov     qword ptr [rbp-10h], 0
.text:00005555555556A5 mov     qword ptr [rbp-28h], 0
.text:00005555555556AD lea     rcx, [rbp-28h]
.text:00005555555556B1 lea     rdx, [rbp-20h]
.text:00005555555556B5 mov     rax, [rbp-38h]
.text:00005555555556B9 mov     rsi, rax
.text:00005555555556BC mov     edi, 3Bh ; ';'
.text:00005555555556C1 mov     eax, 0
.text:00005555555556C6 call    _syscall
.text:00005555555556CB mov     esi, 1
.text:00005555555556D0 mov     edi, 3Ch ; '<'
.text:00005555555556D5 mov     eax, 0
.text:00005555555556DA call    _syscall
.text:00005555555556DF nop
.text:00005555555556E0 mov     rax, [rbp-8]
.text:00005555555556E4 sub     rax, fs:28h
.text:00005555555556ED jz      short locret_5555555556F4
.text:00005555555556EF call    ___stack_chk_fail
.text:00005555555556F4 ; ---------------------------------------------------------------------------
.text:00005555555556F4
.text:00005555555556F4 locret_5555555556F4:                    ; CODE XREF: .text:00005555555556ED↑j
.text:00005555555556F4 leave
.text:00005555555556F5 retn
```

### loc_555555555189
```
.text:0000555555555189 loc_555555555189:                       ; CODE XREF: .text:00005555555551FC↓p
.text:0000555555555189                                         ; .text:0000555555555AD6↓p
.text:0000555555555189 endbr64
.text:000055555555518D push    rbp
.text:000055555555518E mov     rbp, rsp
.text:0000555555555191 mov     [rbp-8], rdi
.text:0000555555555195 jnz     near ptr loc_5555555551A1+1
.text:000055555555519B jz      near ptr loc_5555555551A1+1
.text:00005555555551A1
.text:00005555555551A1 loc_5555555551A1:                       ; CODE XREF: .text:0000555555555195↑j
.text:00005555555551A1                                         ; .text:000055555555519B↑j
.text:00005555555551A1 jmp     near ptr 55554D9ADCEEh
.text:00005555555551A6 ; ---------------------------------------------------------------------------
.text:00005555555551A6 mov     eax, [rax]
.text:00005555555551A8 imul    eax, 19660Dh
.text:00005555555551AE lea     edx, [rax+3C6EF35Fh] // x = x * 0x19660D + 0x3C6EF35F
.text:00005555555551B4 mov     rax, [rbp-8]
.text:00005555555551B8 mov     [rax], edx
.text:00005555555551BA mov     rax, [rbp-8]
.text:00005555555551BE mov     eax, [rax]
.text:00005555555551C0 pop     rbp
.text:00005555555551C1 retn
```

### Program Flow
* The program starts by shuffling the flag using a PRNG.
* The process recursively replace itself with its 'new self' which every life cycle it XOR-check a using a XOR-key (the XOR-key is also changed by the PRNG every life cycle) and the XORed input chracter is checked with a corresponding constant array character.

### Solve script

```python
def lcg32(x):
    return ((x * 0x19660D) + 0x3C6EF35F) & 0xFFFFFFFF

def unshuffle(buf, seed=0x13371337):
    s = seed & 0xFFFFFFFF
    swaps = []
    for i in range(len(buf) - 1, -1, -1):
        s = lcg32(s)
        swaps.append((i, s % (i + 1)))
    for i, j in reversed(swaps):
        buf[i], buf[j] = buf[j], buf[i]

tableB = bytes([
    0x72,0xC3,0x6B,0x0C,0xCF,0x65,0xED,0xBA,0x18,0xCA,0x8F,0x99,
    0xE6,0x8A,0x7F,0xA6,0xE4,0x44,0x4C,0x14,0x5B,0x9E,0x73,0xD3,
    0x61,0xEB,0x44,0x82,0x0D,0xC4,0x07,0xC7,0xE5,0x82,0xE5,0xB7,
    0x0A,0x39,0x4C,0xD2,0x51,0x53,0x05,0x50,0x12,0x6C
])

state = 0x13371337
keys  = []
for _ in range(0x2D):
    state = lcg32(state)

for _ in range(0x2E):
    keys.append(state & 0xFF)
    state = lcg32(state)

tableA = bytearray(b ^ k for b, k in zip(tableB, keys))

unshuffle(tableA)
print(bytes(tableA))

```

Flag: `HCMUS-CTF{d1d_y0u_kn0vv_y0u12_O5_c4n_d0_th1s?}`