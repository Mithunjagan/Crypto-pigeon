package app.cryptopigeon.nativeclient;

import android.system.Os;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.json.JSONObject;

final class NativeIo {
    private NativeIo(){}
    static void directory(File file) throws Exception {if(!file.isDirectory()&&!file.mkdirs())throw new IOException("vault_directory_unavailable");Os.chmod(file.getAbsolutePath(),0700);}
    static byte[] read(InputStream input,int limit) throws Exception {
        try(InputStream stream=input;ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[8192];int n,total=0;while((n=stream.read(buffer))!=-1){total+=n;if(total>limit)throw new IOException("size_limit_exceeded");out.write(buffer,0,n);}return out.toByteArray();
        }
    }
    static byte[] read(File file,int limit) throws Exception {if(file.length()>limit)throw new IOException("size_limit_exceeded");return read(new FileInputStream(file),limit);}
    static JSONObject json(File file,int limit) throws Exception {return new JSONObject(new String(read(file,limit),StandardCharsets.UTF_8));}
    static void atomic(File file,byte[] bytes) throws Exception {
        directory(file.getParentFile());AtomicFile atomic=new AtomicFile(file);FileOutputStream output=atomic.startWrite();
        try{Os.fchmod(output.getFD(),0600);output.write(bytes);output.getFD().sync();atomic.finishWrite(output);}
        catch(Exception failure){atomic.failWrite(output);throw failure;}
    }
    static void atomic(File file,JSONObject value) throws Exception {atomic(file,Crypto.utf8(value.toString()));}
    static File child(File root,String path) throws Exception {
        File file=new File(root,path);if(!file.getCanonicalPath().startsWith(root.getCanonicalPath()+File.separator))throw new SecurityException("invalid_vault_path");return file;
    }
    static void copyTree(File source,File target) throws Exception {
        if(Files.isSymbolicLink(source.toPath()))throw new SecurityException("vault_symlink_not_allowed");
        if(source.isDirectory()){directory(target);File[] files=source.listFiles();if(files==null)throw new IOException("vault_directory_unavailable");for(File file:files)copyTree(file,new File(target,file.getName()));}
        else {directory(target.getParentFile());try(InputStream input=new FileInputStream(source);FileOutputStream output=new FileOutputStream(target)){byte[] buffer=new byte[8192];int n;while((n=input.read(buffer))!=-1)output.write(buffer,0,n);output.getFD().sync();}Os.chmod(target.getAbsolutePath(),0600);}
    }
    static void deleteTree(File file,File allowedParent) throws Exception {
        String parent=allowedParent.getCanonicalPath(),target=file.getCanonicalPath();
        if(!target.startsWith(parent+File.separator)||Files.isSymbolicLink(file.toPath()))throw new SecurityException("invalid_cleanup_path");
        if(file.isDirectory()){File[] children=file.listFiles();if(children==null)throw new IOException("cleanup_failed");for(File child:children)deleteTree(child,allowedParent);}
        if(file.exists()&&!file.delete())throw new IOException("cleanup_failed");
    }
    static void move(File source,File target) throws Exception {if(target.exists()||!source.renameTo(target))throw new IOException("LOCAL_COMMIT_FAILED_RECOVERY_PRESERVED");}
    static JSONObject sealed(Crypto.Sealed value) throws Exception {return new JSONObject().put("nonce",Crypto.b64(value.nonce)).put("ciphertext",Crypto.b64(value.ciphertext));}
    static Crypto.Sealed sealed(JSONObject value) throws Exception {return new Crypto.Sealed(Crypto.unb64(value.getString("nonce")),Crypto.unb64(value.getString("ciphertext")));}
}
