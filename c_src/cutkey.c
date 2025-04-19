/* -------------------------------------------------------------------

   Copyright (c) 2011 Andrew Tunnell-Jones. All Rights Reserved.

   This file is provided to you under the Apache License,
   Version 2.0 (the "License"); you may not use this file
   except in compliance with the License.  You may obtain
   a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.

   -------------------------------------------------------------------- */

#include <erl_driver.h>
#include <ei.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#if ERL_DRV_EXTENDED_MAJOR_VERSION < 2
#define ErlDrvSizeT int
#define ErlDrvSSizeT int
#endif

#if ERL_DRV_EXTENDED_MAJOR_VERSION > 2 || \
   (ERL_DRV_EXTENDED_MAJOR_VERSION == 2 && ERL_DRV_EXTENDED_MINOR_VERSION >= 1)
#define CUTKEY_DRV_OUTPUT_TERM(Port, Result, ResultN) \
  erl_drv_output_term(driver_mk_port(Port), Result, ResultN)
#else
#define CUTKEY_DRV_OUTPUT_TERM(Port, Result, ResultN) \
  driver_output_term(Port, Result, ResultN)
#endif

#if __clang__ && __APPLE__
#define CUTKEY_SILENCE_DEPRECATED_ON_OSX_START            \
  _Pragma("clang diagnostic push");                         \
  _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"");
#define CUTKEY_SILENCE_DEPRECATED_ON_OSX_END  \
  _Pragma("clang diagnostic pop");
#else
#define CUTKEY_SILENCE_DEPRECATED_ON_OSX_START
#define CUTKEY_SILENCE_DEPRECATED_ON_OSX_END
#endif

#define CUTKEY_CMD_RSA     1

#define CUTKEY_ERR_CMD     0
#define CUTKEY_ERR_ARG     1

typedef struct _ck_drv_t {
  ErlDrvPort erl_port;
  ErlDrvTermData term_port;
} ck_drv_t;

typedef struct _ck_job_t {
  ErlDrvPort erl_port;
  unsigned int ref;
  int cmd;
  unsigned int num;
  unsigned int e;
  RSA *rsa;
} ck_job_t;

/* Driver Callbacks */
static ErlDrvData start(ErlDrvPort port, char* cmd);
static void stop(ErlDrvData handle);
static ErlDrvSSizeT call(ErlDrvData drv_data,
			 unsigned int command,
			 char *buf,
			 ErlDrvSizeT len,
			 char **rbuf,
			 ErlDrvSizeT rlen,
			 unsigned int *flags);
static void ready_async(ErlDrvData drv_data, ErlDrvThreadData data);
static void do_rsa_job(void* data);

static ErlDrvEntry cutkey_driver_entry = {
    NULL,                             /* init */
    start,                            /* startup */
    stop,                             /* shutdown */
    NULL,                             /* output */
    NULL,                             /* ready_input */
    NULL,                             /* ready_output */
    "cutkey_drv",                     /* the name of the driver */
    NULL,                             /* finish */
    NULL,                             /* handle */
    NULL,                             /* control */
    NULL,                             /* timeout */
    NULL,                             /* process */
    ready_async,                      /* ready_async */
    NULL,                             /* flush */
    call,                             /* call */
    NULL,                             /* event */
    ERL_DRV_EXTENDED_MARKER,          /* ERL_DRV_EXTENDED_MARKER */
    ERL_DRV_EXTENDED_MAJOR_VERSION,   /* ERL_DRV_EXTENDED_MAJOR_VERSION */
    ERL_DRV_EXTENDED_MINOR_VERSION,   /* ERL_DRV_EXTENDED_MINOR_VERSION */
    ERL_DRV_FLAG_USE_PORT_LOCKING     /* ERL_DRV_FLAGs */
};

DRIVER_INIT(cutkey_driver) {
  return &cutkey_driver_entry;
}

static ErlDrvData start(ErlDrvPort port, char* cmd) {
  ck_drv_t* retval = (ck_drv_t*) driver_alloc(sizeof(ck_drv_t));
  retval->erl_port = port;
  retval->term_port = driver_mk_port(port);
  return (ErlDrvData) retval;
}

static void stop(ErlDrvData edd) {
  ck_drv_t* dd = (ck_drv_t*) edd;
  driver_free(dd);
}

static ErlDrvSSizeT call(ErlDrvData edd, unsigned int cmd, char *buf,
			 ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen,
			 unsigned int *flags) {
  ck_drv_t* dd = (ck_drv_t*) edd;
  int version, out_len, index, rindex, errno;
  ei_term tuple, ref, bits, e;
  char* out_atom_text;
  out_len = 0;
  index = 0;
  rindex = 0;
  errno = CUTKEY_ERR_CMD;
  ei_encode_version(NULL, &out_len);
  ei_encode_version(*rbuf, &rindex);
  ei_decode_version(buf, &index, &version);
  if (cmd == CUTKEY_CMD_RSA) {
    errno = CUTKEY_ERR_ARG;
    ei_decode_ei_term(buf, &index, &tuple);
    if (tuple.ei_type != ERL_SMALL_TUPLE_EXT || tuple.arity != 3) {
      goto error;
    }
    ei_decode_ei_term(buf, &index, &ref);
    if (ref.ei_type != ERL_INTEGER_EXT) {
      goto error;
    }
    ei_decode_ei_term(buf, &index, &bits);
    if (bits.ei_type != ERL_INTEGER_EXT) {
      goto error;
    }
    ei_decode_ei_term(buf, &index, &e);
    if (e.ei_type != ERL_INTEGER_EXT) {
      goto error;
    }
    ck_job_t *job_data = (ck_job_t*) driver_alloc(sizeof(ck_job_t));
    job_data->erl_port = dd->erl_port;
    job_data->ref = ref.value.i_val;
    job_data->cmd = cmd;
    job_data->num = bits.value.i_val;
    job_data->e = e.value.i_val;
    driver_async(dd->erl_port, NULL, do_rsa_job, (void*) job_data, NULL);
    out_atom_text = "ok";
    ei_encode_atom(NULL, &out_len, out_atom_text);
    if(rlen < out_len) {
      *rbuf = driver_alloc(out_len);
      rlen = out_len;
    }
    ei_encode_atom(*rbuf, &rindex, out_atom_text);
  } else {
  error:
    out_atom_text = "error";
    ei_encode_tuple_header(NULL, &out_len, 2);
    ei_encode_atom(NULL, &out_len, out_atom_text);
    ei_encode_long(NULL, &out_len, 99);
    if(rlen < out_len) {
      *rbuf = driver_alloc(out_len);
      rlen = out_len;
    }
    ei_encode_tuple_header(*rbuf, &rindex, 2);
    ei_encode_atom(*rbuf, &rindex, out_atom_text);
    ei_encode_long(*rbuf, &rindex, errno);
  }
  return out_len;
}

static void ready_async(ErlDrvData edd, ErlDrvThreadData async_data) {
  ck_drv_t* dd = (ck_drv_t*) edd;
  ck_job_t* job = (ck_job_t*) async_data;

  if (job->cmd == CUTKEY_CMD_RSA) {
      if (job->rsa != NULL) {
          RSA* rsa = job->rsa;
          const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;

          // Safe accessor APIs for OpenSSL 1.1+ / 3.x
          RSA_get0_key(rsa, &n, &e, &d);
          RSA_get0_factors(rsa, &p, &q);
          RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

          int esize = BN_num_bytes(e);
          int nsize = BN_num_bytes(n);
          int dsize = BN_num_bytes(d);
          int psize = BN_num_bytes(p);
          int qsize = BN_num_bytes(q);
          int dmp1size = BN_num_bytes(dmp1);
          int dmq1size = BN_num_bytes(dmq1);
          int iqmpsize = BN_num_bytes(iqmp);

          unsigned char *e_bin = driver_alloc(esize);
          unsigned char *n_bin = driver_alloc(nsize);
          unsigned char *d_bin = driver_alloc(dsize);
          unsigned char *p_bin = driver_alloc(psize);
          unsigned char *q_bin = driver_alloc(qsize);
          unsigned char *dmp1_bin = driver_alloc(dmp1size);
          unsigned char *dmq1_bin = driver_alloc(dmq1size);
          unsigned char *iqmp_bin = driver_alloc(iqmpsize);

          BN_bn2binpad(e, e_bin, esize);
          BN_bn2binpad(n, n_bin, nsize);
          BN_bn2binpad(d, d_bin, dsize);
          BN_bn2binpad(p, p_bin, psize);
          BN_bn2binpad(q, q_bin, qsize);
          BN_bn2binpad(dmp1, dmp1_bin, dmp1size);
          BN_bn2binpad(dmq1, dmq1_bin, dmq1size);
          BN_bn2binpad(iqmp, iqmp_bin, iqmpsize);

          ErlDrvTermData spec[] = {
              ERL_DRV_PORT, dd->term_port,
              ERL_DRV_UINT, job->ref,
              ERL_DRV_BUF2BINARY, (ErlDrvTermData) e_bin, esize,
              ERL_DRV_BUF2BINARY, (ErlDrvTermData) n_bin, nsize,
              ERL_DRV_BUF2BINARY, (ErlDrvTermData) d_bin, dsize,
              ERL_DRV_BUF2BINARY, (ErlDrvTermData) p_bin, psize,
              ERL_DRV_BUF2BINARY, (ErlDrvTermData) q_bin, qsize,
              ERL_DRV_BUF2BINARY, (ErlDrvTermData) dmp1_bin, dmp1size,
              ERL_DRV_BUF2BINARY, (ErlDrvTermData) dmq1_bin, dmq1size,
              ERL_DRV_BUF2BINARY, (ErlDrvTermData) iqmp_bin, iqmpsize,
              ERL_DRV_NIL,
              ERL_DRV_LIST, 9,
              ERL_DRV_TUPLE, 3
          };

          CUTKEY_DRV_OUTPUT_TERM(dd->erl_port, spec, sizeof(spec) / sizeof(spec[0]));

          driver_free(e_bin);
          driver_free(n_bin);
          driver_free(d_bin);
          driver_free(p_bin);
          driver_free(q_bin);
          driver_free(dmp1_bin);
          driver_free(dmq1_bin);
          driver_free(iqmp_bin);

          RSA_free(rsa);
          driver_free(async_data);
      } else {
          ErlDrvTermData spec[] = {
              ERL_DRV_PORT, dd->term_port,
              ERL_DRV_UINT, job->ref,
              ERL_DRV_ATOM, driver_mk_atom("error"),
              ERL_DRV_TUPLE, 3
          };
          CUTKEY_DRV_OUTPUT_TERM(dd->erl_port, spec, sizeof(spec)/sizeof(spec[0]));
          driver_free(async_data);
      }
  }
}
static void do_rsa_job(void* data) {
  ck_job_t* job = (ck_job_t*) data;
  CUTKEY_SILENCE_DEPRECATED_ON_OSX_START
  job->rsa = RSA_generate_key(job->num, job->e, NULL, NULL);
  CUTKEY_SILENCE_DEPRECATED_ON_OSX_END
}
