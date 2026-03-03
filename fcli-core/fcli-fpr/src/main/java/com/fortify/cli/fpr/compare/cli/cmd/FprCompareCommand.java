/*
 * Copyright 2021-2026 Open Text.
 *
 * The only warranties for products and services of Open Text
 * and its affiliates and licensors ("Open Text") are as may
 * be set forth in the express warranty statements accompanying
 * such products and services. Nothing herein should be construed
 * as constituting an additional warranty. Open Text shall not be
 * liable for technical or editorial errors or omissions contained
 * herein. The information contained herein is subject to change
 * without notice.
 */
package com.fortify.cli.fpr.compare.cli.cmd;

import java.io.File;
import java.nio.file.Path;

import com.fasterxml.jackson.databind.JsonNode;
import com.fortify.cli.common.output.cli.cmd.AbstractOutputCommand;
import com.fortify.cli.common.output.cli.cmd.IJsonNodeSupplier;
import com.fortify.cli.common.output.cli.mixin.OutputHelperMixins;
import com.fortify.cli.fpr.compare.FprCompareHelper;
import com.fortify.cli.fpr.compare.FprCompareHtmlReportHelper;

import lombok.Getter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(
    name = "compare",
    resourceBundle = "com.fortify.cli.fpr.i18n.FprMessages"
)
public class FprCompareCommand extends AbstractOutputCommand implements IJsonNodeSupplier {

    @Getter @Mixin private OutputHelperMixins.DetailsNoQuery outputHelper;

    @Parameters(index = "0", descriptionKey = "fcli.fpr.compare.compare.baseline")
    private Path baseline;

    @Parameters(index = "1", descriptionKey = "fcli.fpr.compare.compare.comparison")
    private Path comparison;

    @Option(names = "--report", descriptionKey = "fcli.fpr.compare.compare.report")
    private File reportFile;

    private JsonNode compareResult;

    @Override
    public JsonNode getJsonNode() {
        if (compareResult == null) {
            compareResult = FprCompareHelper.compare(baseline, comparison);
        }
        return compareResult;
    }

    @Override
    public Integer call() {
        JsonNode result = getJsonNode();
        if (reportFile != null) {
            FprCompareHtmlReportHelper.generateReport(result, reportFile.toPath());
        }
        return super.call();
    }

    @Override
    public boolean isSingular() {
        return true;
    }
}
