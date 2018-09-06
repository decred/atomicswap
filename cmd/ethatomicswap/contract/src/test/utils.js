// Copyright (c) 2018 BetterToken BVBA
// Use of this source code is governed by an MIT
// license that can be found at https://github.com/rivine/rivine/blob/master/LICENSE.

module.exports.sleep = async function(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
};
