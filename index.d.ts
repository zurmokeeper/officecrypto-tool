
/**
 * @author zurmokeeper
 * @time 2023-5-27
 * github home page https://github.com/zurmokeeper/officecrypto-tool
 */


export = officeCrypto;

declare namespace officeCrypto{

    interface Options {
        /**
         * @desc Encrypted/Decrypted passwords, maximum length is 255
         * required
         */
        password: string;
    }

    /**
     * 
     * @param input  The buffer to be encrypted
     * @param options 
     * @description encryption methods,For the time being only support ecma376 agile and ecma376 standard
     */
    function encrypt(input: Buffer, options: Options): Buffer;

    /**
     * @param input  The encrypted buffer
     * @param options 
     * @description decryption methods,For the time being only support ecma376 agile
     */
    function decrypt(input: Buffer, options: Options): Promise<Buffer>;
}