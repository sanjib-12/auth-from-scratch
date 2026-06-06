export interface UserCredentials {
   email: string;
   password: string;
}

export interface ApiResponse {
   status: number;
   message: string;
}

export interface ProfileData {
   message: string;
   email: string;
   mfaEnabled?: boolean;
   emailOtpEnable?: boolean;
}

export interface MfaSetupData {
   secret: string;
   otpauthUri: string;
}

export interface MfaSetupResult {
   recoveryCodes: string[];
}
