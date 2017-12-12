<?php
/*
 * @link      <https://github.com/Genial-Framework/Encryption> for the canonical source repository
 * @copyright Copyright (c) 2017-2018 Genial Framework. <https://github.com/Genial-Framework>
 * @license   <https://github.com/Genial-Framework/Encryption/blob/master/LICENSE> New BSD License
 */
 
namespace Genial\Encryption\Hash;

use Genial\Encryption\Algo;
use Genial\Encryption\Exception\InvalidAlgorithmException;
use Genial\Encryption\Exception\InvalidOperationException;
use Genial\Encryption\Utils;

/**
 * Hash
 */
class Hash extends Algo
{
    /**
     * @const bool|false RAW_OUTPUT Weither to output the raw data by
     *     default.
     */
    const RAW_OUTPUT = false;
    
    /**
     * @var string|null $algo The last supported algorithm used.
     */
    protected static $algo = null;
    
    /**
     * cipher
     *
     * Cipher data by hashing it
     *
     * @param string|null $algo The hashing algorithm to use during
     *     hash execution.
     * @param mixed|null $data The requested data to hash.
     * @param bool|false $rawOutput Weither to output the raw data
     *     of the hash.
     *
     * @throws InvalidAlgorithmException If the algorithm is not supported
     *     or if the algorithm does not exist.
     *
     * @return string The hash from the requested data.
     */
    public static function cipher(string $algo, $data = null, $rawOutput = self::RAW_OUTPUT)
    {
        if (self::supported($algo, REQUEST_HASH_ALGOS))
        {
            self::$algo = $algo;
            $data = Utils::convert($data);
            $rawOutput = (bool) $rawOutput;
            return hash($algo, $data, $rawOutput);
        }
        throw new InvalidAlgorithmException(sprintf(
            '"%s" expects a supported algorithm.',
            __METHOD__
        ));
    }
    
    /**
     * getAlgo
     *
     * Get the last supported algorithm.
     *
     * @throws InvalidOperationException If there is no algorithm
     *     to return.
     *
     * @return string The last supported algorithm used.
     */
    public static function getAlgo()
    {
        if (!is_null(self::$algo)) {
            return self::$algo;
        }
        throw new InvalidOperationException(sprintf(
            '"%s" can not find an algorithm to return.',
            __METHOD__
        ));
    }
    
    /**
     * clearCache
     *
     * Clear the cache of this class.
     *
     * @return void
     */
    public static function clearCache()
    {
        if (!is_null(self::$algo))
        {
            self::$algo = null;
        }
    }
    
}
