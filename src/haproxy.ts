import * as ssh from "node-ssh";
import * as sha256 from "sha256";
import { ILogger, LoggerFactory } from '@log4js-universal/logger';
import { Configuration, IConfiguration, IConfigurationEntry, EType, IGlobalDB, IWebService } from "dockerproxy-commons";

export class HAProxy implements IWebService {
    private static LOGGER: ILogger = LoggerFactory.getLogger("dockerproxy.Scheduler");
    private sshInstance: Promise<ssh.default> = null;

    public stop(): Promise<void> {
        if (this.sshInstance) {
            return this.sshInstance.then((connection) => {
                connection.dispose();
                this.sshInstance = null;
            });
        }
        return Promise.resolve();
    }

    public getConfEntries(): IConfigurationEntry[] {
        return [
            { name: 'haProxyHost', mandatory: true, type: EType.STRING },
            { name: 'haProxyPort', mandatory: true, type: EType.NUMBER },
            { name: 'haProxyUsername', mandatory: true, type: EType.STRING },
            { name: 'haProxyPassword', mandatory: true, type: EType.STRING },
            { name: 'haProxyFolder', mandatory: true, type: EType.STRING },
            { name: 'haProxyHTTPPort', mandatory: true, type: EType.NUMBER },
            { name: 'haProxyHTTPSPort', mandatory: false, type: EType.NUMBER },
            { name: 'haProxyForceHTTPS', mandatory: false, type: EType.BOOLEAN },
            { name: 'haProxySSLCertificatsPath', mandatory: false, type: EType.STRING },
            { name: 'haProxyReloadCommand', mandatory: true, type: EType.STRING },
        ];
    }

    public updateConf(db: IGlobalDB): Promise<void> {
        return Configuration.INSTANCE.getConfig<IConfigurationProxy>().then((config) => {
            const filesToWrite: Array<{
                path: string,
                content: string
            }> = [];
            const frontends: Array<{
                backend: string;
                domains?: string[];
                paths?: string[];
                authents?: string[];
            }> = [];
            const files: { [key: string]: boolean } = {};
            return this.getSSHConnection().then((connection) => {
                return connection.exec('mkdir', ['-p', config.haProxyFolder]).then((stdout) => {
                    return connection.exec('find', [config.haProxyFolder]);
                }).then((stdout) => {
                    stdout.split('\n').forEach((entry) => {
                        files[entry] = true;
                    });
                    delete files[config.haProxyFolder];
                }).then(() => {
                    // Prepare all backend files contents
                    db.services.forEach((service) => {
                        for (const internalPort in service.PORT) {
                            let contentConf: string = 'backend bk_' + service.NAME + '_' + internalPort;
                            frontends.push({
                                backend: 'backend bk_' + service.NAME + '_' + internalPort,
                                domains: service.domains,
                                authents: service.authent,
                                paths: service.paths
                            });
                            service.authent.forEach((authent, index) => {
                                contentConf += '\n\tacl AuthOK_ELAO' + index + ' http_auth(' + authent + ')';
                                contentConf += '\n\thttp-request auth realm ' + authent + ' if !AuthOK_ELAO' + index;
                            });
                            service.nodes.forEach((node, index) => {
                                contentConf += '\n\tserver srv' + index + ' ' + node.IP + ':' + service.PORT[internalPort];
                            });
                            contentConf += '\n';
                            const configFilename: string = 'backend_' + service.NAME + '_' + internalPort + '.cfg';
                            const configFilePath: string = config.haProxyFolder + configFilename;
                            filesToWrite.push({
                                path: configFilePath,
                                content: contentConf
                            });
                        };
                    });
                }).then(() => {
                    // Write all configs files if necessary
                    return connection.requestSFTP().then((sftp: any) => {
                        const promisesWrite: Promise<boolean>[] = [];
                        //Write frontend
                        let content: string = "";
                        if (config.haProxyHTTPSPort && config.haProxyForceHTTPS) {
                            content = "frontend fronthttp";
                            content += '\n\tbind *:' + config.haProxyHTTPPort;
                            content += '\n\thttp-request redirect scheme https';
                            content += '\n';
                            content += '\nfrontend fronthttps';
                            content += '\n\tbind *:' + config.haProxyHTTPSPort + ' ssl';
                            frontends.forEach((frontend) => {
                                frontend.domains.forEach((domain) => {
                                    content += ' crt ' + config.haProxySSLCertificatsPath + domain + '/' + domain + '.pem';
                                });
                            });
                        } else {
                            content = "frontend front";
                            content += '\n\tbind *:' + config.haProxyHTTPPort;
                            if (config.haProxyHTTPSPort) {
                                content += '\n\tbind :' + config.haProxyHTTPSPort + ' ssl';
                                frontends.forEach((frontend) => {
                                    frontend.domains.forEach((domain) => {
                                        content += ' crt ' + config.haProxySSLCertificatsPath + domain + '/' + domain + '.pem';
                                    });
                                });
                            }
                        }
                        frontends.forEach((frontend, index) => {
                            let rules: string = '';
                            frontend.domains.forEach((domain) => {
                                content += '\n\tacl host-index-' + index + ' hdr(host) eq ' + domain;
                                rules += ' host-index-' + index;
                            });
                            frontend.paths.forEach((path) => {
                                content += '\n\tacl path-prefix-' + index + ' path_beg ' + path;
                                rules += ' path-prefix-' + index;
                            });
                            content += '\n\tuse_backend ' + frontend.backend;
                            if (rules.length > 0) {
                                content += ' if' + rules;
                            }
                        });
                        const configFilePath: string = config.haProxyFolder + 'frontend';
                        promisesWrite.push(this.updateFile(sftp, files, configFilePath, content));

                        //Write backends
                        filesToWrite.forEach((fileToWrite) => {
                            promisesWrite.push(this.updateFile(sftp, files, fileToWrite.path, fileToWrite.content));
                        });
                        return Promise.all(promisesWrite).then((isUpdated: boolean[]) => {
                            if (isUpdated.find(p => p === true)) {
                                // Must reload haproxy
                                return connection.execCommand(config.haProxyReloadCommand).then(() => { });
                            }
                        });
                    });
                })
            })
        });
    }

    protected updateFile(connectionSFTP: any, files: { [key: string]: boolean }, filePath: string, content: string): Promise<boolean> {
        let promiseCalculation: Promise<boolean> = null;
        const sha = sha256.default(content);
        if (files[filePath]) {
            delete files[filePath];
            promiseCalculation = this.getSSHConnection().then((ssh) => {
                return ssh.exec('sha256sum', [filePath]).then((stdout) => {
                    HAProxy.LOGGER.debug("Sum file : '%1', Sum new calculation: '%2'", stdout.substr(0, 64), sha);
                    return stdout.substr(0, 64) !== sha;
                });
            });
        } else {
            promiseCalculation = Promise.resolve(true);
        }
        return promiseCalculation.then((mustBeUpdated: boolean) => {
            if (mustBeUpdated) {
                HAProxy.LOGGER.info("Doit mettre à jour %1", filePath);
                return new Promise<boolean>((resolveWrite) => {
                    const writer = connectionSFTP.createWriteStream(filePath);
                    writer.on('close', () => {
                        resolveWrite(true);
                    });
                    writer.write(content);
                    writer.end();
                })
            } else {
                HAProxy.LOGGER.info("Pas a mettre à jour %1", filePath)
                return false;
            }
        })
    }

    protected getSSHConnection(): Promise<ssh.default> {
        if (!this.sshInstance) {
            this.sshInstance = Configuration.INSTANCE.getConfig<IConfigurationProxy>().then((config) => {
                return new Promise<ssh.default>((resolve, reject) => {
                    const connection = new ssh.default();
                    connection.connect({
                        host: config.haProxyHost,
                        password: config.haProxyUsername,
                        port: config.haProxyPort,
                        username: config.haProxyPassword,
                    }).then(() => {
                        resolve(connection);
                    }, (e) => {
                        reject(e);
                    });
                });
            });
        }
        return this.sshInstance;
    }
}

export interface IConfigurationProxy extends IConfiguration {
    haProxyHost: string;
    haProxyPort: number;
    haProxyUsername: string;
    haProxyPassword: string;
    haProxyFolder: string;
    haProxyHTTPPort: number;
    haProxyHTTPSPort?: number;
    haProxyForceHTTPS?: boolean;
    haProxySSLCertificatsPath?: string;
    haProxyReloadCommand: string;
}