<?php

namespace Tests\Feature;

use Illuminate\Http\Request;
use Tests\TestCase;

class SmokeTest extends TestCase
{
    public function testHealthEndpointResponds(): void
    {
        $this->get('/up')->assertStatus(200);
    }

    public function testBenchmarkRoutesAreRegistered(): void
    {
        $route = app('router')->getRoutes()->match(Request::create('/vuln/invoices/1'));

        $this->assertSame('App\Http\Controllers\Vuln\InvoiceController@show', $route->getActionName());
    }
}
