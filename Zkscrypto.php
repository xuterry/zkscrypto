<?php
namespace zkscrypto;

class Zkscrypto
{
    protected $engine_file = '';

    protected $engine = null;

    protected $u = null;

    protected $msg;

    protected $priv;

    protected $pub;

    protected $pub_hase;

    protected $priv_add;

    protected $pub_add;

    function __construct($msg = 'hello')
    {
        $this->engine_file = __DIR__ . DS . 'zks_crypto.so';
        if (! is_file($this->engine_file))
            throw new \Exception(' crypto file not exist ');
        if (! extension_loaded('ffi')) {
            throw new \Exception(' ffi lib not exist ');
        }
        $this->msg = $msg;
        $this->init();
    }

    protected function get_priv()
    {
        if (! empty($this->priv))
            return $this->priv;
        $arg_type = \FFI::arrayType($this->engine->type('uint8_t'), [
                                                                        65
        ]);
        $a = $this->engine->new($arg_type);
        $getsign = $this->u->arrayify($this->msg);
        foreach ($getsign as $k => $v)
            $a[$k] = $v;
        $priv = \FFI::addr($this->engine->new('ZksPrivateKey'));
        $this->engine->zks_crypto_private_key_from_seed($a, 65, $priv);
        $this->priv = $this->u->hexlify($priv->data);
        $this->priv_add = $priv;
        return $this->priv;
    }

    protected function init()
    {
        if (!empty($this->engine))
            return;
        $this->u = new \Utils();
        if(stripos(php_sapi_name(),'cli')===false)
            $this->engine=\FFI::load(__DIR__.DS.'zks_crypto.h');
        else
            $this->engine = \FFI::scope("Zkscrypto");
        $this->engine->zks_crypto_init();
        $this->get_priv();
    }

    function sign($array)
    {
        $sign = \FFI::addr($this->engine->new('ZksSignature'));
        $signarr = [];
        foreach ($array as $v) {
            $signarr = array_merge($signarr, $this->u->arrayify($v));
        }
        $sign_len = count($signarr);
        $arg_type = \FFI::arrayType($this->engine->type('uint8_t'), [
                                                                        $sign_len
        ]);
        $a = $this->engine->new($arg_type);
        foreach ($signarr as $k => $v)
            $a[$k] = $v;
        $this->engine->zks_crypto_sign_musig($this->priv_add, $a, $sign_len, $sign);
        return $this->u->hexlify($sign->data);
    }

    function pub()
    {
        $pub = \FFI::addr($this->engine->new('ZksPackedPublicKey'));
        $this->engine->zks_crypto_private_key_to_public_key($this->priv_add, $pub);
        $this->pub_add = $pub;
        $this->pub = $this->u->hexlify($pub->data);
        return $this->pub;
    }

    function pub_hash()
    {
        if(empty($this->pub_add))
            $this->pub();
        $pub_hash = \FFI::addr($this->engine->new('ZksPubkeyHash'));
        $this->engine->zks_crypto_public_key_to_pubkey_hash($this->pub_add, $pub_hash);
        return $this->u->hexlify($pub_hash->data);
    }
    function rescueHashOrders($array)
    {
        $signarr = [];
        foreach ($array as $v) {
            $signarr = array_merge($signarr, $this->u->arrayify($v));
        }
        $sign_len = count($signarr);
        $arg_type = \FFI::arrayType($this->engine->type('uint8_t'), [
            $sign_len
        ]);
        $a = $this->engine->new($arg_type);
        foreach ($signarr as $k => $v)
            $a[$k] = $v;
            $pub = \FFI::addr($this->engine->new('ZksResqueHash'));
            $this->engine->rescue_hash_orders($a,$sign_len, $pub);
            return $this->u->hexlify($pub->data);
    }

    function __destruct()
    {
        empty($this->pub_add)||\FFI::free($this->pub_add);
    }
}