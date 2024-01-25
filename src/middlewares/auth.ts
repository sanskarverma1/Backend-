import { NextFunction, Request, Response } from "express";
import { UnauthorizedException } from "../exceptions/unauthorized";
import { ErrorCode } from "../exceptions/root";
import * as jwt from 'jsonwebtoken'
import { JWT_SECRET } from "../secrets";
import { prismaClient } from "..";

const authMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    // 1. Extract the token from header
    const token = req.headers.authorization;

    // 2. if token is not present throw an error of unauthorized
    if (!token) {
        next(new UnauthorizedException('Unauthorized', ErrorCode.UNAUTHORIZED));
        return; // Ensure we exit the function after calling `next`
    }

    // 3. if token is present, verify the token and extract the payload
    try {
        const payload = jwt.verify(token as string, JWT_SECRET) as any;

        // 4. get the user from the payload
        const user = await prismaClient.user.findFirst({ where: { id: payload.userId } });

        // 5. if user is null, throw an error of unauthorized
        if (!user) {
            next(new UnauthorizedException('Unauthorized', ErrorCode.UNAUTHORIZED));
           // return; // Ensure we exit the function after calling `next`
        }

        // 6. to attach the user to the current req object
        req.user = user;
        next(); // Continue to the next middleware or route handler
    } catch (error) {
        next(new UnauthorizedException('Unauthorized', ErrorCode.UNAUTHORIZED));
    }
}

export default authMiddleware;
