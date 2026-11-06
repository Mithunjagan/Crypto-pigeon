package app.cryptopigeon.nativeclient;

import android.util.Base64OutputStream;
import java.io.*;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/** Only encrypted databases/files reach disk; plaintext snapshot JSON is streamed in memory. */
final class SnapshotCodec {
    static final int MAX_COMPRESSED=64*1024*1024-16,MAX_PLAINTEXT=256*1024*1024,MAX_FILES=10000;
    private SnapshotCodec(){}
    private static final class WipingBuffer extends ByteArrayOutputStream {void wipe(){Arrays.fill(buf,(byte)0);reset();}}
    private static final class LimitedOutput extends FilterOutputStream {
        private final int maximum;private int count;
        LimitedOutput(OutputStream out,int maximum){super(out);this.maximum=maximum;}
        @Override public void write(int value) throws IOException {if(++count>maximum)throw new IOException("backup_too_large");out.write(value);}
        @Override public void write(byte[] bytes,int offset,int length) throws IOException {if(length>maximum-count)throw new IOException("backup_too_large");count+=length;out.write(bytes,offset,length);}
    }
    static byte[] encode(File database,File attachments,byte[] vmk,String hkdfSalt) throws Exception {
        WipingBuffer compressed=new WipingBuffer();
        try(GZIPOutputStream gzip=new GZIPOutputStream(new LimitedOutput(compressed,MAX_COMPRESSED))){
            OutputStream json=new LimitedOutput(gzip,MAX_PLAINTEXT);
            json.write(Crypto.utf8("{\"format\":1,\"vmk\":"+VaultWire.quote(Crypto.b64(vmk))+",\"hkdfSalt\":"+VaultWire.quote(hkdfSalt)+",\"database\":\""));
            base64File(json,database);json.write(Crypto.utf8("\",\"files\":{"));
            File[] files=attachments.isDirectory()?attachments.listFiles():new File[0];if(files==null)throw new IOException("attachment_directory_unavailable");
            int count=0;boolean first=true;
            for(File file:files){
                if(!file.getName().matches("[a-f0-9]{32}"))continue;
                if(!file.isFile()||java.nio.file.Files.isSymbolicLink(file.toPath()))throw new IOException("invalid_attachment_path");
                if(++count>MAX_FILES)throw new IOException("too_many_backup_files");
                json.write(Crypto.utf8((first?"":",")+VaultWire.quote(file.getName())+":\""));first=false;
                base64File(json,file);json.write('"');
            }
            json.write(Crypto.utf8("}}"));gzip.finish();return compressed.toByteArray();
        }finally{compressed.wipe();}
    }
    private static void base64File(OutputStream out,File file) throws Exception {
        try(InputStream input=new FileInputStream(file);Base64OutputStream base64=new Base64OutputStream(out,android.util.Base64.NO_WRAP|android.util.Base64.NO_CLOSE)){
            byte[] buffer=new byte[8192];int n;while((n=input.read(buffer))!=-1)base64.write(buffer,0,n);
        }
    }
    static final class Snapshot implements AutoCloseable {
        byte[] vmk;String salt;
        @Override public void close(){Crypto.wipe(vmk);vmk=null;}
    }
    static Snapshot decode(byte[] compressed,File stage) throws Exception {
        Snapshot result=new Snapshot();boolean complete=false;
        try(InputStream gzip=new GZIPInputStream(new ByteArrayInputStream(compressed))){
            Parser parser=new Parser(gzip);NativeIo.directory(new File(stage,"data"));NativeIo.directory(new File(stage,"attachments"));
            parser.expect('{');Set<String> fields=new HashSet<>();boolean first=true;
            while(parser.peekNonSpace()!='}'){
                if(!first)parser.expect(',');first=false;String key=parser.string(32);if(!fields.add(key))throw new IOException("duplicate_snapshot_field");parser.expect(':');
                switch(key){
                    case "format":if(parser.number()!=1.0)throw new IOException("invalid_snapshot_format");break;
                    case "vmk":result.vmk=Crypto.unb64(parser.string(44));if(result.vmk.length!=32)throw new IOException("invalid_snapshot_key");break;
                    case "hkdfSalt":result.salt=parser.string(24);if(Crypto.unb64(result.salt).length!=16)throw new IOException("invalid_snapshot_salt");break;
                    case "database":parser.base64(new File(stage,"data/chat.db"));break;
                    case "files":
                        parser.expect('{');Set<String> names=new HashSet<>();boolean firstFile=true;
                        while(parser.peekNonSpace()!='}'){
                            if(!firstFile)parser.expect(',');firstFile=false;String name=parser.string(32);
                            if(!name.matches("[a-f0-9]{32}")||!names.add(name)||names.size()>MAX_FILES)throw new IOException("invalid_snapshot_path");
                            parser.expect(':');parser.base64(NativeIo.child(new File(stage,"attachments"),name));
                        }
                        parser.expect('}');break;
                    default:throw new IOException("unsupported_snapshot_field");
                }
            }
            parser.expect('}');if(parser.peekNonSpace()!=-1||!fields.containsAll(Arrays.asList("format","vmk","hkdfSalt","database")))throw new IOException("invalid_snapshot");
            complete=true;return result;
        }finally{if(!complete)result.close();}
    }
    /** Small metadata strings and incremental base64 blobs prevent decompression/string bombs. */
    private static final class Parser {
        private final InputStream input;private int next=-2,total;
        Parser(InputStream input){this.input=new BufferedInputStream(input,8192);}
        int peek() throws IOException {if(next==-2){next=input.read();if(next!=-1&&++total>MAX_PLAINTEXT)throw new IOException("snapshot_too_large");}return next;}
        int take() throws IOException {int value=peek();next=-2;return value;}
        int peekNonSpace() throws IOException {while(peek()==' '||peek()=='\r'||peek()=='\n'||peek()=='\t')take();return peek();}
        void expect(int expected) throws IOException {if(peekNonSpace()!=expected)throw new IOException("invalid_snapshot_json");take();}
        int character() throws IOException {
            int value=take();if(value==-1||value<32)throw new IOException("invalid_snapshot_string");
            if(value=='\\'){
                int escaped=take();switch(escaped){case '"':case '\\':case '/':return escaped;case 'b':return '\b';case 'f':return '\f';case 'n':return '\n';case 'r':return '\r';case 't':return '\t';case 'u':
                    int code=0;for(int i=0;i<4;i++){int digit=Character.digit((char)take(),16);if(digit<0)throw new IOException("invalid_snapshot_escape");code=(code<<4)|digit;}return code;
                    default:throw new IOException("invalid_snapshot_escape");}
            }
            return value;
        }
        String string(int limit) throws IOException {
            expect('"');StringBuilder value=new StringBuilder();while(peek()!='"'){int c=character();if(c>127||value.length()>=limit)throw new IOException("snapshot_metadata_too_large");value.append((char)c);}take();return value.toString();
        }
        double number() throws IOException {
            peekNonSpace();StringBuilder number=new StringBuilder();while(peek()!=-1&&",}] \r\n\t".indexOf(peek())<0){if(number.length()>=32)throw new IOException("invalid_snapshot_number");number.append((char)take());}
            String text=number.toString();if(!text.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?"))throw new IOException("invalid_snapshot_number");return Double.parseDouble(text);
        }
        void base64(File file) throws Exception {
            expect('"');byte[] encoded=new byte[8192];int length=0;boolean padded=false;
            try(FileOutputStream output=new FileOutputStream(file)){
                while(peek()!='"'){
                    int c=character();boolean valid=c>='A'&&c<='Z'||c>='a'&&c<='z'||c>='0'&&c<='9'||c=='+'||c=='/'||c=='=';
                    if(!valid||padded&&c!='=')throw new IOException("invalid_snapshot_base64");if(c=='=')padded=true;
                    encoded[length++]=(byte)c;
                    if(length==encoded.length){if(padded&&peek()!='"')throw new IOException("invalid_snapshot_base64");output.write(java.util.Base64.getDecoder().decode(encoded));length=0;}
                }
                take();if(length>0)output.write(java.util.Base64.getDecoder().decode(Arrays.copyOf(encoded,length)));output.getFD().sync();
            }finally{Crypto.wipe(encoded);}
        }
    }
}
