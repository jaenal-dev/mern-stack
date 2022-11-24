import { Router } from 'express';
import passport from 'passport';

import TransactionsApi from './TransactionsApi.js';
import AuthApi from './AuthApi.js';
import UserApi from './UserApi.js';
import CategoryApi from './CategoryApi.js';

const routes = Router();

const auth = passport.authenticate('jwt', { session: false });

routes.use('/transaction', auth, TransactionsApi);
routes.use('/auth', AuthApi);
routes.use('/user', UserApi);
routes.use('/category', auth, CategoryApi);

export default routes;
