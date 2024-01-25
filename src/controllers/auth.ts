import {NextFunction, Request,Response} from 'express'
import {prismaClient} from'..'
import { hashSync, compareSync } from 'bcrypt';
import * as jwt from 'jsonwebtoken'
import { JWT_SECRET } from '../secrets';
import { BadRequestsException } from '../exceptions/bad-request';
import { ErrorCode } from '../exceptions/root';
import { UnprocessableEntity } from '../exceptions/validation';
import { SignUpSchema } from '../schema/users';
import { NotFoundException } from '../exceptions/not-found';

export const signup =async (req:Request,res:Response, next:NextFunction)=>{
    SignUpSchema.parse(req.body)
        const {email,password,name}=req.body;
        let user=await prismaClient.user.findFirst({where: {email}})
        if(user){
             (new BadRequestsException('User Already Exists', ErrorCode.USER_ALREADY_EXISTS))
        }
        user = await prismaClient.user.create({
            data:{
                name,
                email,
                password: hashSync(password,10)
            }
        })
        res.json(user)

    
}

export const login =async (req:Request,res:Response)=>{
    const {email,password}=req.body;
    let user=await prismaClient.user.findFirst({where: {email}})
    if(!user){
        throw new NotFoundException('User Not Found',ErrorCode.USER_NOT_FOUND)
    }
    if(!compareSync(password,user.password)) {
        throw new BadRequestsException('Incorrect Password', ErrorCode.INCORRECT_PASSWORD)

    }
    const token = jwt.sign({
        userId:user.id
    },JWT_SECRET);
   
    res.json({user,token})
}
