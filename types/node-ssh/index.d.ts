export default class SSH {
    connect(params: IConnectParams): Promise<void>;
    exec(command: string, params: string[], opts?: IExecOpts): Promise<string>;
    execCommand(command: string, opts?: IExecOpts): Promise<IStd>;
    dispose() : void;
    requestSFTP: any;
}

export interface IConnectParams {
    host: string;
    port?: number;
    password?: string;
    username: string;
    privateKey?: string;
}

export interface IStd {
    stdout: string;
    stderr: string;
}

export interface IExecOpts {
    cwd?: string,
    options?: Object // passed to ssh2.exec
    stdin?: string,
    stream?: 'stdout' | 'stderr' | 'both',
    onStdout?: ((chunk: Buffer) => void),
    onStderr?: ((chunk: Buffer) => void),
}