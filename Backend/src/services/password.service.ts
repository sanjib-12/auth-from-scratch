import crypto from "crypto";

function hashedPassword(password: string): string{
   const salt = crypto.randomBytes(16).toString('hex');

   const hash = crypto
      .pbkdf2Sync(password, salt, 10000, 64, 'sha512')
      .toString('hex');
   return `${salt}:${hash}`

}

function compareHashedPassword(password: string, stored: string): boolean{
   const [salt, originHash] = stored.split(':');

   const hash = crypto
         .pbkdf2Sync(password, salt, 10000, 64, 'sha512')
         .toString('hex');
   
   return hash === originHash;
}

export { hashedPassword, compareHashedPassword }