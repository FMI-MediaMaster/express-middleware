import { Request, Response, NextFunction, RequestHandler } from 'express';
import { ZodError, ZodIssue } from 'zod';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import chalk from 'chalk';

declare global {
    namespace Express {
        interface Request {
            userId?: string | object
        }
        interface Response {
            ok(data: object): Response;
            created(data: object): Response;
            noContent(): Response;
            badRequest(data: string | object): Response;
            unauthorized(data?: string): Response;
            forbidden(data?: string): Response;
            notFound(data?: string): Response;
            conflict(data?: string): Response;
            internalError(data?: string): Response;
            unknownEndpoint(): Response;
        }
    }
}

const sendSuccess = (res: Response, status: number, data?: object): Response => {
    return res.status(status).json(data);
};

const sendError = (res: Response, status: number, data: string | object): Response => {
    if (typeof data === 'string') {
        return res.status(status).json({ error: data });
    } else {
        return res.status(status).json(data);
    }
};

export const responseExtensions = (req: Request, res: Response, next: NextFunction): void => {
    Object.assign(res, {
        ok(this: Response, data: object): Response {
            return sendSuccess(this, 200, data);
        },

        created(this: Response, data: object): Response {
            return sendSuccess(this, 201, data);
        },

        noContent(this: Response): Response {
            return sendSuccess(this, 204);
        },

        badRequest(this: Response, data: string | object): Response {
            return sendError(this, 400, data);
        },

        unauthorized(this: Response, data?: string): Response {
            return sendError(this, 401, data || 'Unauthorized');
        },

        forbidden(this: Response, data?: string): Response {
            return sendError(this, 403, data || 'Forbidden');
        },

        notFound(this: Response, data?: string): Response {
            return sendError(this, 404, data || 'Not found');
        },

        conflict(this: Response, data?: string): Response {
            return sendError(this, 409, data || 'Conflict');
        },

        internalError(this: Response, data?: string): Response {
            return sendError(this, 500, data || 'Internal server error');
        },

        unknownEndpoint(this: Response): Response {
            return sendError(this, 404, 'Endpoint not found');
        }
    });
    next();
};

interface Config {
    NODE_ENV?: string;
    [key: string]: unknown
};

export const requestLogger = (config: Config): RequestHandler => {
    if (config.NODE_ENV === 'test') {
        return (req, res, next) => next();
    }

    return morgan((tokens, req, res) => {
        const status = Number(tokens.status(req, res)) || 0;
        const method = tokens.method(req, res) || '';
        const url = tokens.url(req, res) || '';
        const responseTime = tokens['response-time'](req, res) || '';

        const isSuccess = status >= 200 && status < 400;
        const color = isSuccess ? chalk.green : chalk.red;

        const coloredMethod = color(method);
        const coloredStatus = color(status.toString());

        return `${coloredMethod} ${url} ${coloredStatus} - ${responseTime} ms`;
    });
};

export const unknownEndpoint = (req: Request, res: Response): void => {
    res.unknownEndpoint();
};

export const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
    if (!req.userId) {
        res.unauthorized();
        return;
    }
    next();
};

export const userExtractor = (secret: string) => (req: Request, res: Response, next: NextFunction): void => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token) {
        try {
            req.userId = jwt.verify(token, secret);
        } catch {
            res.unauthorized('Invalid token');
            return;
        }
    }
    next();
};

export const errorHandler = (
    err: unknown,
    req: Request,
    res: Response,
    next: NextFunction
): void => {
    const error = err as any;

    console.error({
        time: new Date().toISOString(),
        method: req.method,
        path: req.originalUrl,
        user: req.userId ?? 'anonymous',
        message: error.message ?? 'Unknown error',
        stack: error.stack,
        body: req.body,
        query: req.query,
        params: req.params,
    });

    if (res.headersSent) {
        next(err);
    } else if (error instanceof ZodError) {
        const issues: { path: string; message: string }[] = error.issues.map((e: ZodIssue) => ({
            path: e.path.join('.'),
            message: e.message,
        }));
        res.badRequest({ errors: issues });
    } else if (error.name === 'UnauthorizedError' || error.status === 401) {
        res.unauthorized(error.message);
    } else if (error.status === 403) {
        res.forbidden(error.message);
    } else if (error.status === 404) {
        res.notFound(error.message);
    } else if (error.status === 409) {
        res.conflict(error.message);
    } else {
        res.internalError('Unexpected error');
    }
};
