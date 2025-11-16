import { UserRepo } from "../../repository/user/user.repo.js";

interface IQuery {}

interface IQueryHandler<T> {
    handle(qry: IQuery): Promise<T>
}

export {IQuery, IQueryHandler};