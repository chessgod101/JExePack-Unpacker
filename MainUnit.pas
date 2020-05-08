unit MainUnit;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, IdCompressorZLib, ShellAPI;

type
  TJUMain = class(TForm)
    UnpackBtn: TButton;
    PathEdit: TEdit;
    OWCheckBox: TCheckBox;
    ChooseBtn: TButton;
    OpenDialog1: TOpenDialog;
    Label1: TLabel;
    WebsiteBtn: TButton;
    procedure UnpackBtnClick(Sender: TObject);
    procedure ChooseBtnClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);

  private
    { Private declarations }
  public
    { Public declarations }
  protected
    procedure WMDropFiles(var Msg: TMessage); message WM_DROPFILES;
  end;

Type FHeader= Packed Record
 SecIdentity:Array[0..13] of AnsiChar;
 secType:array [0..1] of AnsiChar;
 res:array [0..7] of byte;
 size:cardinal;
 res2:cardinal;
End;

Type DHeader = Packed Record
 SecIdentity:Cardinal;
 len:Byte;
End;
Type PDHeader =^DHeader;
Type PFHeader = ^FHeader;

CONST
SECTION_IDENTITY:AnsiString='JKMNPQSTVWYZ\]';
JAR_INFO_SECTION:AnsiString='_V';
JEXEPACK_BOOT_FILE:AnsiString='_B';
JEXEPACK_JAVAINSTALL_MODULE='_J';
JEXEPACK_COMPRESSED_SECTION:AnsiString='_Z';

var
  JUMain: TJUMain;
implementation

{$R *.dfm}

Function DetectSectionType(inp:AnsiString):Cardinal;
CONST
 secHeaders:Array[0..3] of ansistring=('_V','_B','_J','_Z');
var
 I:Byte;
Begin
 for I := 0 to 3 do Begin
  if inp=secHeaders[I] then begin
   Result:=I;
   Exit;
  end;
 End;
 Result:=4;
End;

Procedure DecryptSection(buf:PByte;len:Cardinal);
var
 I:Cardinal;
Begin
 dec(len);
 for I := 0 to len do begin
  buf[I]:=(buf[I] xor I)-$64;
 end;
End;

Function FindNextFileL(buf:PByte;size:Cardinal;var rOffset:Cardinal):Boolean;
var
 I:cardinal;
Begin
 result:=false;
 if size<=14 then exit;
 size:=size-14;
 for I := 0 to size do begin
  if CompareMem(@buf[I],@SECTION_IDENTITY[1],14)= true then begin
   Result:=true;
   rOffset:=I;
   exit;
  end;
end;

End;

Function SaveFile(FileName:wideString;data:Pbyte;size:Cardinal;overwrite:Boolean):Boolean;
var
 fh:THandle;
 tmp:cardinal;
Begin
 result:=false;
 if overwrite=true then
  tmp:=CREATE_ALWAYS
 else
  tmp:=CREATE_NEW;
 fh:=CreateFile(@FileName[1],GENERIC_WRITE,0,NIL,tmp,FILE_ATTRIBUTE_NORMAL,0);
 if fh<>INVALID_HANDLE_VALUE then begin
  if WriteFile(fh,data[0],size,tmp,nil)=true then
   result:=true;
  CloseHandle(fh);
 end;
End;


Function GetOffsetOfAppendedData(fH:THandle;Var offset:Cardinal):Boolean;
var
 dh:tImageDosHeader;
 pe:timageFileHeader;
 secH:TImageSectionHeader;
 tmp:Cardinal;
Begin
 result:=false;
 offset:=0;
 SetFilePointer(fH,0,nil,FILE_BEGIN);
 if ReadFile(fH,dh,sizeof(TImageDosHeader),tmp,nil)=false then exit;
 if dh.e_magic<>23117 then exit;
 SetFilePointer(fH,dh._lfanew+4,nil,FILE_BEGIN);
 if ReadFile(fH,pe,sizeof(TImageFileHeader),tmp,nil)=false then exit;
 SetFilePointer(fH,pe.SizeOfOptionalHeader+(sizeof(TImageSectionHeader)*(pe.NumberOfSections-1)),nil,FILE_CURRENT);
 if ReadFile(fH,secH,sizeof(TImageSectionHeader),tmp,nil)=false then exit;
 offset:=secH.SizeOfRawData+secH.PointerToRawData;
 result:=true;
End;

Procedure UnpackJEXEPack(fileN:WideString;overwrite:boolean);
var
 sOffset,fSize,secSize,tmp,FileSize,IV:cardinal;
 saveDir:widestring;
 fHandle:THandle;
 className:AnsiString;
 buffer:array of byte;
 TOffset,AOffset,MOffset:PByte;
 t:PFHeader;
 ms,ns:TMemoryStream;
 iDecompress:TIdCompressorZLib;
 dhdr:PDHeader;
 strmSize:Int64;
begin
 saveDir:=ExtractFilePath(fileN)+'unpacked_files\';

 if FileExists(String(fileN))=false then Begin
  MessageBox(JUMain.Handle,PChar('File Does Not Exist!'),PChar('JexePack Unpacker'), MB_OK);
  exit;
 End;

 if ForceDirectories(saveDir)=false then begin
  MessageBox(JUMain.Handle,PChar('Force Directories Failed'),PChar('JexePack Unpacker'), MB_OK);
  exit;
 End;

 fHandle:=CreateFileW(@fileN[1],GENERIC_READ, FILE_SHARE_READ, NIL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

 if fHandle = INVALID_HANDLE_VALUE then begin
  MessageBox(JUMain.Handle, PChar('Failed to Open File!'), PChar('JexePack Unpacker'), MB_OK);
  exit;
 End;

 if GetOffsetOfAppendedData(fHandle,soffset)=False then begin
  MessageBox(JUMain.Handle, PChar('Not a valid PE File. Not a JexePack File.'), PChar('JexePack Unpacker'), MB_OK);
  CloseHandle(fHandle);
  exit;
 End;

 fSize:=GetFileSize(fHandle,nil);

 if fSize<=sOffset then begin
  MessageBox(JUMain.Handle, PChar('Not a JexePack File.'), PChar('JexePack Unpacker'), MB_OK);
  CloseHandle(fHandle);
 End;

 secSize:=fSize-sOffset;
 Setlength(buffer,secSize);
 SetFilePointer(fHandle, sOffset, nil, 0);

 if ReadFile(fHandle, buffer[0], secSize, tmp, nil)=False then begin
  MessageBox(JUMain.Handle, PChar('Failed to Read File.'), PChar('JexePack Unpacker'), MB_OK);
  CloseHandle(fHandle);
  exit;
 End;

 CloseHandle(fHandle);
 AOffset:=@buffer[0];
 tmp:=0;
 IV:=0;

 Repeat
  AOffset:=pByte(Cardinal(AOffset)+tmp);
  t:=PFHeader((AOffset));
  TOffset:=@AOffset[28];
  if (t.SecIdentity<>SECTION_IDENTITY) and (t.SIZE>(secsize-(cardinal(AOffset)-cardinal(@buffer[0])))) then break;

  case DetectSectionType(t.secType) of
   0://JEXEPACK_BOOT_FILE:
   Begin
    DecryptSection(TOffset,t.size);
    className:='jexepackboot.class';
    SaveFile(saveDir+WideString(className),TOffset,t.size,overwrite);
   End;

   1://JAR_INFO_SECTION:
   Begin
    className:='FileInformation.txt';
    SaveFile(saveDir+WideString(className),TOffset,t.size,overwrite);
   End;

   2://JEXEPACK_JAVAINSTALL_MODULE:
   Begin
    DecryptSection(TOffset,t.size);
    SaveFile(saveDir+'JavaInst'+inttostr(IV)+'.exe',TOffset,t.size,overwrite);
    IV:=IV+1;
   End;

   3://JEXEPACK_COMPRESSED_SECTION:
   Begin
    DecryptSection(TOffset,t.size);
    ms:=TMemoryStream.Create;
    ms.Write(TOffset[8],t.size-8);
    ms.Position:=0;
    ns:=TmemoryStream.Create;
    try
    iDecompress:=TIdCompressorZLib.create();
    iDecompress.DecompressGZipStream(ms,ns);
    iDecompress.Free;
    Except
    MessageBox(JUMain.Handle,PChar('Failed to Decompress File.'),PChar('JexePack Unpacker'), MB_OK);
    ms.Free;
    ns.Free;
    exit;
    end;
    ms.Free;
    ns.Position:=0;
    TOffset:=ns.Memory;
    strmSize:=ns.Size;
    mOffset:=TOffset;
    repeat
     dhdr:=pointer(MOffset);
     if dhdr.SecIdentity<>$eadc12f0 then Break;
     setlength(className,dhdr.len);
     CopyMemory(@className[1],@MOffset[5],dhdr.len);
     MOffset:=@MOffset[5+dhdr.len+1];
     FileSize:=pCardinal(MOffset)^;
     MOffset:=@MOffset[4];
     if Cardinal(MOffset)-cardinal(TOffset)+FileSize>ns.size then break;
     SaveFile(saveDir+WideString(className), MOffset, FileSize, overwrite);
     MOffset:=@MOffset[FileSize];
    until moffset-TOffset>=strmSize;
    TOffset:=@AOffset[28];
    ns.free;
   End;
  end;  //end case

  AOffset:=PByte(Cardinal(TOffset)+t.size);
 Until FindNextFileL(Aoffset,secsize-(cardinal(AOffset)-cardinal(@buffer[0])),tmp)=false;

 MessageBeep(MB_ICONINFORMATION);
 MessageBox(Application.Handle,PChar('Done! Check upacked_files folder in app directory.'),PChar('JexePack Unpacker'), MB_OK);
end;

procedure TJUMain.UnpackBtnClick(Sender: TObject);
Begin
 UnpackJEXEPack(PathEdit.Text,OWCheckBox.Checked);
end;

procedure TJUMain.WMDropFiles(var Msg: TMessage);
var
 l:cardinal;
 s,ext:string;
Begin
 l:=DragQueryFile(Msg.WParam,0,nil,0)+1;
 SetLength(s,l);
 DragQueryFile(Msg.WParam,0,Pointer(s),l);
 ext:= lowercase(TrimRight(ExtractFileExt(s)));
 if ext='.exe' then PathEdit.Text:=s;
End;

procedure TJUMain.ChooseBtnClick(Sender: TObject);
begin
 if OpenDialog1.Execute=true then
  PathEdit.Text:=OpenDialog1.FileName;
end;

procedure TJUMain.FormCreate(Sender: TObject);
begin
 DragAcceptFiles(Handle,true);
end;

procedure TJUMain.FormDestroy(Sender: TObject);
begin
 DragAcceptFiles(Handle,false);
end;

end.
