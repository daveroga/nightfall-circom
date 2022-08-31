module.exports = async ({ getNamedAccounts, deployments }) => {
    const { deploy } = deployments;
    const { deployer } = await getNamedAccounts();

    await deploy('Verifier_deposit', {
        from: deployer,
        log: true
    });
    await deploy('Verifier_transfer', {
        from: deployer,
        log: true
    });
    await deploy('Verifier_withdraw', {
        from: deployer,
        log: true
    });
};
module.exports.tags = ['complete'];
