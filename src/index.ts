import {WhatsAppNumber,ChatNumber,PasskeyCredential,SessionId} from "./nominal.ts";
export * from "./nominal.ts";
export interface EvolutionGoClient{checkWhatsAppExists(chatNumber:string):Promise<boolean>;sendMessage(chatNumber:string,message:string):Promise<void>}
export interface PasskeyAuthenticator{validate(passkey:string,sessionId:string):Promise<boolean>}
export interface AuthResult{authenticated:boolean;sessionId:string}
export interface ChannelResult{web:string;whatsapp:string}
export async function requestLogin(input:unknown,evolution:EvolutionGoClient,makeMagicLink:(chatNumber:string)=>Promise<string>):Promise<{chatNumber:string;magicLink:string}>{
 const chatNumber=WhatsAppNumber.validate(input);
 if(!(await evolution.checkWhatsAppExists(chatNumber)))throw new Error("WhatsApp number does not exist");
 const magicLink=await makeMagicLink(chatNumber);await evolution.sendMessage(chatNumber,magicLink);return{chatNumber,magicLink}
}
export async function completePasskey(passkeyInput:unknown,sessionInput:unknown,auth:PasskeyAuthenticator):Promise<AuthResult>{
 const passkey=PasskeyCredential.validate(passkeyInput);const sessionId=SessionId.validate(sessionInput);
 return{authenticated:await auth.validate(passkey,sessionId),sessionId}
}
export async function centralChatbotMessage(input:unknown,sessionActive:boolean,evolution:EvolutionGoClient,makeMagicLink:(chatNumber:string)=>Promise<string>){
 const chatNumber=ChatNumber.validate(input);
 if(sessionActive)return{authenticated:true,chatNumber};
 const magicLink=await makeMagicLink(chatNumber);await evolution.sendMessage(chatNumber,magicLink);return{authenticated:false,chatNumber,magicLink}
}
export function adaptAuthenticatedResult():ChannelResult{return{web:"Login realizado com sucesso usando a passkey vinculada a este WhatsApp.",whatsapp:"Você acabou de fazer login com a passkey deste WhatsApp."}}
