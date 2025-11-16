interface ICommand {
    commandId: string;  
}

interface ICommandHandler<T> {
    handle(cmd: ICommand): Promise<T>
}

export {ICommand, ICommandHandler};