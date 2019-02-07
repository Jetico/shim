
#include "dgst.h"
#include <efilib.h>

#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ossl_typ.h>
#include <openssl/buffer.h>

#include "OpenSSL/crypto/bio/bio_lcl.h"

#include "shim.h"

EVP_PKEY * dgstPrepareKey();
void dgstVerify(BIO *bp, unsigned char *sigin, int siglen);

const BIO_METHOD * DGST_s_file(void);
BIO * DGST_new_file(const char *_path, const char *mode);

#define BUFSIZE 1024*8

int DGST_verifyFile(const char * _dataFile, const char * _sigFile)
{
    BIO * bmd = BIO_new(BIO_f_md());
    if (bmd == NULL) {
        perror(L"DGST_verify allocation error 1\n");
        return 0;
    }

    EVP_MD_CTX * mctx = NULL;

    if (!BIO_get_md_ctx(bmd, &mctx)) {
        perror(L"DGST_verify Error getting context 1\n");
        return 0;
    }

    ENGINE * impl = NULL;
    EVP_PKEY_CTX * pctx = NULL;

    if (EVP_add_digest (EVP_sha256 ()) == 0) {
      return 0;
    }
    const EVP_MD * md = EVP_get_digestbyname("sha256");

    EVP_PKEY * sigkey = dgstPrepareKey();

    int r = EVP_DigestVerifyInit(mctx, &pctx, md, impl, sigkey);
    if (!r) {
        perror(L"Error setting context\n");
    }

    BIO * sigbio = DGST_new_file(_sigFile, "r");
    if (!sigbio) {
        perror(L"Error opening signature file\n");
        return 0;
    }
    int siglen = EVP_PKEY_size(sigkey);
    unsigned char * sigbuf = AllocatePool(siglen);
    siglen = BIO_read(sigbio, sigbuf, siglen);
    if (siglen < 0) {
        perror(L"Error read signature file\n");
        return 0;
    }
    BIO_free(sigbio);


    BIO * in  = DGST_new_file(_dataFile, "r");
    if (in == NULL) {
        perror(L"DGST_verify allocation error 1\n");
        return 0;
    }
    BIO * inp = BIO_push(bmd, in);

    unsigned char *buf = AllocatePool(BUFSIZE);
    for (;;) {
        int i = BIO_read(inp, (char *)buf, BUFSIZE);
        if (i < 0) {
            perror(L"Error read data file\n");
            return 0;
        }
        if (i == 0)
            break;
    }
    FreePool(buf);

    if (sigbuf) {
        EVP_MD_CTX *ctx;
        BIO_get_md_ctx(inp, &ctx);
        int i = EVP_DigestVerifyFinal(ctx, sigbuf, (unsigned int)siglen);
        if (i > 0) {
            ;//console_print(L"Verified OK\n");
        } else if (i == 0) {
            perror(L"Verification Failure\n");
            return 0;
        } else {
            perror(L"Error Verifying Data\n");
            return 0;
        }
    }

    BIO_free(in);
    BIO_free(bmd);
    FreePool(sigbuf);

    EVP_PKEY_free(sigkey);

    return 1;
}

int dgstGetDigestFileName(const char * _fileName, char * _dgstName, unsigned int _dgstBufSize)
{
   if (_fileName == NULL || _dgstName == NULL) return 0;

   UINTN fileNameLen = strlena((const CHAR8 *)_fileName);

   if (fileNameLen >= _dgstBufSize + 5) return 0;

   UINTN i;
   for (i=0; i<fileNameLen; ++i) {
       _dgstName[i] = _fileName[i];
   }
   char * dgstSuffix = ".dgst";
   for (; i<fileNameLen + 5; ++i) {
       _dgstName[i] = dgstSuffix[i - fileNameLen];
   }
   _dgstName[fileNameLen + 5] = 0;
   return 1;
}

#define LIST_BUF_SIZE 1024
#define LIST_FILES_NUM 16
#define LIST_FILE_LEN 64
int DGST_verifyAll(CHAR16 error[ERROR_MSG_LEN])
{
    console_print(L"Verifying integrity...\n");

    if (!DGST_verifyFile("\\efi_boot.lst", "\\efi_boot.lst.dgst")) {
        perror(L"efi_boot.lst is not signed properly\n");
        StrnCpy(error, L"Verification failed: files list is not signed properly", ERROR_MSG_LEN * 2);
        return 0;
    }

    BIO * listbio = DGST_new_file("\\efi_boot.lst", "r");
    if (listbio == 0) {
        perror(L"Unable to create file object\n");
        StrnCpy(error, L"Verification failed: unable to create file object", ERROR_MSG_LEN * 2);
        return 0;
    }

    char listBuf[LIST_BUF_SIZE];
    int listSize = BIO_read(listbio, (char *)listBuf, LIST_BUF_SIZE);
    if (listSize < 0) {
        perror(L"Unable to read boot files list\n");
        StrnCpy(error, L"Verification failed: unable to read boot files list", ERROR_MSG_LEN * 2);
        BIO_free(listbio);
        return 0;
    }

    char files[LIST_FILES_NUM][LIST_FILE_LEN];
    int i, index = 0;
    for (i=0; i<LIST_FILES_NUM; ++i) {
        int j = 0;
        while (listBuf[index] != '\n') {
            if (j < LIST_FILE_LEN - 1) {
                files[i][j] = listBuf[index];
                ++j;
            }
            ++index;
        }
        files[i][j] = 0;
        ++index;
        if (index >= listSize) break;
    }
    ++i;
    for (; i<LIST_FILES_NUM; ++i) {
        files[i][0] = 0;
    }

    i = 0;
    while (files[i][0] != 0 && i < LIST_FILES_NUM) {
        char buf[70];
        if (!dgstGetDigestFileName(files[i], buf, 70)) {
            SPrint(error, ERROR_MSG_LEN * 2, L"Verification failed: unable to construct digest file name for %a", files[i]);
            return 0;
        }

        if (!DGST_verifyFile(files[i], buf)) {
            perror(L"%a is not signed properly\n", files[i]);
            SPrint(error, ERROR_MSG_LEN * 2, L"Verification failed: %a is not signed properly", files[i]);
            return 0;
        }
        ++i;
    }
    console_print(L"Verified OK\n");
    return 1;
}

EVP_PKEY * dgstPrepareKey()
{
    const unsigned char * keyRawData = (const unsigned char *)
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqHz2evD4F4BDcdE0W6Zq\n\
1A9vO+7zPvSgE44Ld8cBzLRlCYZo4MgTxUiwwbhVm571iEgu1Z07k4seLFNzInTu\n\
zrzYSZ8X4mcUGAVp6U9utXQszrCtfSb+yiRoB5oiAmNfjgd+6fHhlXtoFboLpV1f\n\
QifL0Hh9uCB1cyH8J6ev9KCGVF5f1oKlGNSz2juNdrYjXHmlxQ+apxRhmUE8+2+2\n\
BHvMTIiT6XUOgMkFjY6uhKiL3gAWFIItuSUJ0dSrnTVkmx16V2ruF81ZYspVKORE\n\
nK8rmO6Ckaxwm9D6gjnc9FpZoWSFdZoNAx7A0s9H5p9Zv9YKrv72PY8wiuR6Kgzp\n\
NwIDAQAB\n";

    int keyDataLen = 0, k = 0;
    EVP_PKEY * sigkey = NULL;

    BUF_MEM * keyData = BUF_MEM_new();
    keyDataLen = 399;

    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    while (1) {
        EVP_DecodeInit(ctx);
        int i = EVP_DecodeUpdate(ctx, (unsigned char *)keyData->data, &keyDataLen, keyRawData, keyDataLen);
        if (i < 0) {
            perror(L"dgstPrepareKey error key decode update\n");
            break;
        }
        i = EVP_DecodeFinal(ctx, (unsigned char *)&(keyData->data[keyDataLen]), &k);
        if (i < 0) {
            perror(L"dgstPrepareKey error decode final\n");
            break;
        }
        keyDataLen += k;

        const unsigned char *p = (unsigned char *)keyData->data;
        sigkey = d2i_PUBKEY(NULL, &p, keyDataLen);
        if (sigkey == NULL) {
            perror(L"dgstPrepareKey Unable to init verification key\n");
            break;
        }
        break;
    }
    EVP_ENCODE_CTX_free(ctx);
    BUF_MEM_free(keyData);

    return sigkey;
}

static int dgstFileWrite(BIO *b, const char *in, int inl)
{
    return -1;
}
static int dgstFileRead(BIO * b, char * out, int outl)
{
    if (b->init && (out != NULL)) {

    }
    UINTN bufferSize = (UINTN)outl;

    EFI_STATUS status = ((EFI_FILE_HANDLE)b->ptr)->Read((EFI_FILE_HANDLE)b->ptr, &bufferSize, (VOID*)out);
    if (EFI_ERROR(status)) {
        perror(L"dgstFileRead error 1 status %u\n", status);
        return -1;
    }
    return (int)bufferSize;

}
static int dgstFilePuts(BIO *bp, const char *str)
{
    return -1;
}
static int dgstFileGets(BIO *bp, char *buf, int size)
{
    return 0;
}
static int dgstFileFree(BIO *a)
{
    if (a == NULL) {
        return 0;
    }
    if (a->shutdown) {
        if ((a->init) && (a->ptr != NULL)) {
            EFI_STATUS status = ((EFI_FILE_HANDLE)a->ptr)->Close((EFI_FILE_HANDLE)a->ptr);
            if (EFI_ERROR(status)) {
                return 0;
            }
            a->ptr = NULL;
        }
        a->init = 0;
    }
    return 1;
}
static long dgstFileCtrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;

    switch (cmd) {
    case BIO_C_FILE_SEEK:
        ;//console_print(L"dgstFileCtrl BIO_C_FILE_SEEK\n");
        break;
    case BIO_CTRL_RESET:
        ;//console_print(L"dgstFileCtrl BIO_CTRL_RESET\n");
        break;
    case BIO_CTRL_EOF:
        ;//console_print(L"dgstFileCtrl BIO_CTRL_EOF\n");
        break;
    case BIO_C_FILE_TELL:
        ;//console_print(L"dgstFileCtrl BIO_C_FILE_TELL\n");
        break;
    case BIO_CTRL_INFO:
        ;//console_print(L"dgstFileCtrl BIO_CTRL_INFO\n");
        break;
    case BIO_C_SET_FILE_PTR:
        ;//console_print(L"dgstFileCtrl BIO_C_SET_FILE_PTR\n");
        dgstFileFree(b);
        b->shutdown = (int)num & BIO_CLOSE;
        b->ptr = ptr;
        b->init = 1;
        break;
    case BIO_C_SET_FILENAME:
        ;//console_print(L"dgstFileCtrl BIO_C_SET_FILENAME\n");
        break;
    case BIO_C_GET_FILE_PTR:
        ;//console_print(L"dgstFileCtrl BIO_C_GET_FILENAME\n");
        break;
    case BIO_CTRL_GET_CLOSE:
        ;//console_print(L"dgstFileCtrl BIO_C_GET_FILENAME\n");
        ret = (long)b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_FLUSH:
        ;//console_print(L"dgstFileCtrl BIO_CTRL_FLUSH\n");
        break;
    case BIO_CTRL_DUP:
        ;//console_print(L"dgstFileCtrl BIO_CTRL_DUP\n");
        ret = 1;
        break;
    case BIO_CTRL_WPENDING:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
        ;//console_print(L"dgstFileCtrl BIO_CTRL_POP\n");
        break;
    default:
        ;//console_print(L"dgstFileCtrl unknown command\n");
    }
    return ret;
}
static int dgstFileNew(BIO *bi)
{
    bi->init = 0;
    bi->num = 0;
    bi->ptr = 0;
    bi->flags = 0;
    return (1);
}
static const BIO_METHOD methods_dgst = {
    BIO_TYPE_FILE,
    "dgst",
    dgstFileWrite,
    dgstFileRead,
    dgstFilePuts,
    dgstFileGets,
    dgstFileCtrl,
    dgstFileNew,
    dgstFileFree,
    NULL,
};

const BIO_METHOD * DGST_s_file(void)
{
    return (&methods_dgst);
}

extern EFI_HANDLE global_image_handle;

BIO * DGST_new_file(const char *_path, const char *mode)
{
    EFI_LOADED_IMAGE_PROTOCOL * LoadedImage;
    EFI_STATUS status = gBS->HandleProtocol(global_image_handle, &gEfiLoadedImageProtocolGuid, (VOID*)&LoadedImage);

    if (EFI_ERROR(status)) {
        perror(L"DGST_new_file ERROR Unable to open loaded image volume\n");
        return NULL;
    }
    EFI_HANDLE curDevHandle = LoadedImage->DeviceHandle;

    UINTN pathLen = strlena((const CHAR8 *)_path);
    if (curDevHandle == NULL || _path == NULL || pathLen == 0  /*|| !_isOpenModeValid(_mode)*/) {
        perror(L"DGST_new_file invalid argument\n");
        return NULL;
    }

    CHAR16 uniPath[256], i;
    if (pathLen >= 256) {
        perror(L"DGST_new_file path too long %a\n", _path);
        return NULL;
    }
    for (i=0; i<pathLen; ++i) {
        uniPath[i] = (CHAR16)_path[i];
    }
    uniPath[pathLen] = 0;


    EFI_FILE_IO_INTERFACE  *Volume;
    EFI_FILE_HANDLE        Root, newFile;

    status = gBS->HandleProtocol(curDevHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID*)&Volume);
    if (EFI_ERROR(status)) {
        perror(L"DGST_new_file unable to handle simple file system protocol %s\n", uniPath);
        return NULL;
    }

    status = Volume->OpenVolume(Volume, &Root);
    if (EFI_ERROR(status)) {
        perror(L"DGST_new_file unable to open volume\n");
        return NULL;
    }

    status = Root->Open(Root, &newFile, uniPath, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        gBS->CloseProtocol(Volume, &gEfiSimpleFileSystemProtocolGuid, curDevHandle, NULL);
        perror(L"DGST_new_file unable to open file %u: %s\n", status, _path);
        return NULL;
    }

    Root->Close(Root);
    gBS->CloseProtocol(Volume, &gEfiSimpleFileSystemProtocolGuid, curDevHandle, NULL);

    BIO * ret = BIO_new(DGST_s_file());
    if (ret == NULL) {
        //fclose(file);
        perror(L"DGST_new_file BIO allocation error\n");
        return NULL;
    }
    BIO_set_fp(ret, newFile, /*fp_flags*/ 0);
    return ret;
}
