<?php

namespace App\Tests\Controller;

use Doctrine\Common\DataFixtures\Executor\ORMExecutor;
use Doctrine\Common\DataFixtures\Loader;
use Doctrine\Common\DataFixtures\Purger\ORMPurger;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Tools\SchemaTool;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Component\Console\Input\StringInput;
use Symfony\Component\Console\Output\NullOutput;

/**
 * Class AbstractControllerTest
 * @package App\Tests\Controller
 */
abstract class AbstractControllerTest extends WebTestCase
{
    /**
     * @var EntityManager $manager
     */
    private EntityManager $manager;

    /**
     * @var ORMExecutor $executor
     */
    private ORMExecutor $executor;

    /**
     * @var KernelBrowser $client
     */
    protected KernelBrowser $client;

    /**
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        // FIX: Calling "Symfony\Bundle\FrameworkBundle\Test\WebTestCase::createClient()"
        // while a kernel has been booted is deprecated since Symfony 4.4 and will throw in 5.0,
        // ensure the kernel is shut down before calling the method.
        // https://github.com/symfony/symfony-docs/issues/12961#issuecomment-576021219
        self::ensureKernelShutdown();

        // Configure variables
        $this->client = static::createClient();
        $this->manager = self::$kernel->getContainer()->get('doctrine.orm.entity_manager');
        $this->executor = new ORMExecutor($this->manager, new ORMPurger());

        // Run the schema update tool using our entity metadata
        $schemaTool = new SchemaTool($this->manager);
        $schemaTool->updateSchema($this->manager->getMetadataFactory()->getAllMetadata());
    }

    /**
     * @param $fixture
     * @return void
     */
    protected function loadFixture($fixture): void
    {
        $loader = new Loader();

        $fixtures = is_array($fixture) ? $fixture : [$fixture];

        foreach ($fixtures as $item) {
            $loader->addFixture($item);
        }

        $this->executor->execute($loader->getFixtures());
    }

    /**
     * @param string $input
     * @throws \Exception
     */
    protected function runCommand(string $input): void
    {
        $application = new Application(self::$kernel);
        $application->setAutoExit(false);

        $application->run(new StringInput($input), new NullOutput());
    }

    /**
     * @param string $token
     * @return array
     */
    protected static function getAuthHeaders(string $token): array
    {
        return [
            'HTTP_AUTHORIZATION' => "bearer {$token}",
            'CONTENT_TYPE' => 'application/ld+json',
            'HTTP_ACCEPT' => 'application/ld+json'
        ];
    }

    /**
     * @return void
     */
    public function tearDown(): void
    {
        (new SchemaTool($this->manager))->dropDatabase();
    }
}